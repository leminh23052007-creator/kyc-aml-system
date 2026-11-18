import csv
import heapq
import io
import os
import random
import sqlite3
from flask import Flask, jsonify, render_template, request, Response

try:
    import pyodbc
except ImportError:
    pyodbc = None

app = Flask(__name__)

# ==============================================================================
# 1. LỚP TRỪU TƯỢNG KẾT NỐI DATABASE (TỰ ĐỘNG CHỌN SQL SERVER HOẶC SQLITE CLOUD)
# ==============================================================================
USE_SQL_SERVER = (os.name == "nt") and (pyodbc is not None) and (os.environ.get("FORCE_SQLITE") != "1")
SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kyc_aml_cloud.db")


def get_db_connection():
    if USE_SQL_SERVER:
        drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]
        driver_name = drivers[-1] if drivers else "SQL Server"
        conn_str = (
            f"DRIVER={{{driver_name}}};"
            r"SERVER=.\SQLEXPRESS;"
            "DATABASE=KYC_AML_DB;"
            "Trusted_Connection=yes;"
            "TrustServerCertificate=yes;"
        )
        return pyodbc.connect(conn_str), "MSSQL"
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        return conn, "SQLITE"


def init_sqlite_if_needed():
    """Tự động khởi tạo cấu trúc 4 bảng & dữ liệu gốc khi chạy trên Cloud"""
    if USE_SQL_SERVER:
        return
    conn, _ = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS KhachHang (
            ma_kh TEXT PRIMARY KEY,
            ho_ten TEXT NOT NULL,
            loai_kh TEXT NOT NULL,
            quoc_tich TEXT NOT NULL,
            nganh_nghe TEXT NOT NULL,
            la_pep INTEGER NOT NULL DEFAULT 0,
            cau_truc_phuc_tap INTEGER NOT NULL DEFAULT 0,
            giao_dich_du_kien REAL NOT NULL DEFAULT 0,
            diem_rui_ro INTEGER NOT NULL DEFAULT 0,
            phan_loai TEXT NOT NULL,
            trang_thai TEXT NOT NULL,
            ly_do TEXT NULL,
            ngay_cap_nhat DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS CauHinhTrongSo (
            ma_tieu_chi TEXT PRIMARY KEY,
            ten_tieu_chi TEXT NOT NULL,
            diem_trong_so INTEGER NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS BlacklistSanctions (
            ho_ten TEXT PRIMARY KEY,
            nguon_canh_bao TEXT NOT NULL DEFAULT 'UNSCR/OFAC'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS QuocGiaNCCT (
            ma_quoc_gia TEXT PRIMARY KEY,
            ten_quoc_gia TEXT NOT NULL,
            phan_nhom_fatf TEXT NOT NULL
        )
    """)

    # Nạp dữ liệu gốc nếu bảng CauHinhTrongSo đang trống
    cursor.execute("SELECT COUNT(*) FROM CauHinhTrongSo")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO CauHinhTrongSo (ma_tieu_chi, ten_tieu_chi, diem_trong_so) VALUES (?, ?, ?)",
            [
                ("QUOC_TICH_NCCT", "Quốc tịch thuộc danh sách rủi ro cao FATF (NCCT)", 40),
                ("LA_PEP", "Khách hàng / UBO là cá nhân có ảnh hưởng chính trị (PEP/RCA)", 35),
                ("LOAI_KH_RUI_RO", "Loại hình khách hàng rủi ro cao (NGO / Nước ngoài)", 25),
                ("CAU_TRUC_PHUC_TAP", "Cấu trúc sở hữu phức tạp / Công ty bình phong", 25),
                ("NGANH_NHAY_CAM", "Ngành nghề kinh doanh nhạy cảm (Crypto, Casino, Kim loại quý...)", 20),
                ("HAN_MUC_LON", "Hạn mức giao dịch dự kiến > 1.000 triệu VNĐ/tháng", 15),
                ("NGUONG_EDD", "Ngưỡng điểm kích hoạt Thẩm định nâng cao (EDD)", 60),
                ("NGUONG_CDD_TC", "Ngưỡng điểm kích hoạt Thẩm định tiêu chuẩn (CDD)", 30),
            ],
        )

    cursor.execute("SELECT COUNT(*) FROM BlacklistSanctions")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO BlacklistSanctions (ho_ten, nguon_canh_bao) VALUES (?, ?)",
            [
                ("NGUYEN VAN XAU", "UNSCR 1267"),
                ("TRAN THI RUA TIEN", "OFAC SDN"),
                ("VIKTOR BOUT", "UNSCR/OFAC"),
                ("CONG TY MA OFFSHORE LTD", "OFAC SDN"),
                ("GLOBAL DARK TRADING CORP", "UNSCR 1988"),
            ],
        )

    cursor.execute("SELECT COUNT(*) FROM QuocGiaNCCT")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO QuocGiaNCCT (ma_quoc_gia, ten_quoc_gia, phan_nhom_fatf) VALUES (?, ?, ?)",
            [
                ("IR", "Cộng hòa Hồi giáo Iran", "Call for Action (Danh sách Đen)"),
                ("KP", "Cộng hòa Dân chủ Nhân dân Triều Tiên", "Call for Action (Danh sách Đen)"),
                ("MM", "Cộng hòa Liên bang Myanmar", "Call for Action (Danh sách Đen)"),
                ("SY", "Cộng hòa Ả Rập Syria", "Giám sát tăng cường"),
                ("YE", "Cộng hòa Yemen", "Giám sát tăng cường"),
                ("AF", "Afghanistan", "Rủi ro cao về AML/CFT"),
            ],
        )

    conn.commit()
    conn.close()


NGANH_NHAY_CAM = {"Crypto", "Casino", "Doi_tien", "Kim_loai_quy", "Thuong_mai_QT"}


# ==============================================================================
# 2. LỚP LÕI HỆ THỐNG KYC/AML (DICT + SET + MIN-HEAP + STACK + DATABASE)
# ==============================================================================
class HeThongKYCAMLWeb:
    def __init__(self):
        self.ho_so_dict = {}
        self.blacklist_set = set()
        self.ncct_set = set()
        self.trong_so = {}
        self.edd_heap = []
        self.lich_su_stack = []
        self.thu_tu_nhap = 0
        init_sqlite_if_needed()
        self.tai_du_lieu_tu_db()

    def tai_du_lieu_tu_db(self):
        self.ho_so_dict.clear()
        self.blacklist_set.clear()
        self.ncct_set.clear()
        self.trong_so.clear()
        self.edd_heap.clear()
        self.thu_tu_nhap = 0

        conn, _ = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT ma_tieu_chi, ten_tieu_chi, diem_trong_so FROM CauHinhTrongSo")
        for row in cursor.fetchall():
            self.trong_so[row[0]] = {
                "ten": row[1],
                "diem": int(row[2]),
            }

        cursor.execute("SELECT ho_ten FROM BlacklistSanctions")
        for row in cursor.fetchall():
            self.blacklist_set.add(row[0].strip().upper())

        cursor.execute("SELECT ma_quoc_gia FROM QuocGiaNCCT")
        for row in cursor.fetchall():
            self.ncct_set.add(row[0].strip().upper())

        cursor.execute("""
            SELECT ma_kh, ho_ten, loai_kh, quoc_tich, nganh_nghe,
                   la_pep, cau_truc_phuc_tap, giao_dich_du_kien,
                   diem_rui_ro, phan_loai, trang_thai, ly_do
            FROM KhachHang
            ORDER BY ngay_cap_nhat ASC, ma_kh ASC
        """)
        for row in cursor.fetchall():
            ma_kh = row[0].strip().upper()
            hs = {
                "ma_kh": ma_kh,
                "ho_ten": row[1].strip().upper(),
                "loai_kh": row[2],
                "quoc_tich": row[3].strip().upper(),
                "nganh_nghe": row[4],
                "la_pep": bool(row[5]),
                "cau_truc_phuc_tap": bool(row[6]),
                "giao_dich_du_kien": float(row[7]),
                "diem_rui_ro": int(row[8]),
                "phan_loai": row[9],
                "trang_thai": row[10],
                "ly_do": row[11].split("; ") if row[11] else [],
            }
            self.ho_so_dict[ma_kh] = hs
            if hs["phan_loai"] == "EDD" and hs["trang_thai"] == "CHO_THAM_DINH":
                self.thu_tu_nhap += 1
                heapq.heappush(self.edd_heap, (-hs["diem_rui_ro"], self.thu_tu_nhap, ma_kh))

        conn.close()

    def danh_gia_ho_so(self, ho_so):
        ho_ten = str(ho_so["ho_ten"]).strip().upper()
        quoc_tich = str(ho_so["quoc_tich"]).strip().upper()

        if ho_ten in self.blacklist_set:
            return (
                100,
                "TU_CHOI_CAM_VAN",
                "DA_TU_CHOI",
                ["Trùng khớp danh sách trừng phạt UNSCR/OFAC"],
            )

        diem = 0
        ly_do = []
        w = self.trong_so

        if quoc_tich in self.ncct_set:
            d = w.get("QUOC_TICH_NCCT", {}).get("diem", 40)
            diem += d
            ly_do.append(f"Quốc tịch rủi ro cao FATF ({quoc_tich}) (+{d}đ)")

        if ho_so["la_pep"]:
            d = w.get("LA_PEP", {}).get("diem", 35)
            diem += d
            ly_do.append(f"Khách hàng/UBO thuộc diện PEP/RCA (+{d}đ)")

        if ho_so["loai_kh"] in {"NGO", "Nuoc_ngoai"}:
            d = w.get("LOAI_KH_RUI_RO", {}).get("diem", 25)
            diem += d
            ly_do.append(f"Loại hình rủi ro cao: {ho_so['loai_kh']} (+{d}đ)")

        if ho_so["cau_truc_phuc_tap"]:
            d = w.get("CAU_TRUC_PHUC_TAP", {}).get("diem", 25)
            diem += d
            ly_do.append(f"Cấu trúc sở hữu phức tạp / Công ty vỏ bọc (+{d}đ)")

        if ho_so["nganh_nghe"] in NGANH_NHAY_CAM:
            d = w.get("NGANH_NHAY_CAM", {}).get("diem", 20)
            diem += d
            ly_do.append(f"Ngành nghề nhạy cảm: {ho_so['nganh_nghe']} (+{d}đ)")

        if float(ho_so["giao_dich_du_kien"]) > 1000:
            d = w.get("HAN_MUC_LON", {}).get("diem", 15)
            diem += d
            ly_do.append(f"Hạn mức GD lớn: {ho_so['giao_dich_du_kien']} tr/tháng (+{d}đ)")

        diem = min(diem, 100)
        nguong_edd = w.get("NGUONG_EDD", {}).get("diem", 60)
        nguong_cdd = w.get("NGUONG_CDD_TC", {}).get("diem", 30)

        if diem >= nguong_edd:
            phan_loai = "EDD"
            trang_thai = "CHO_THAM_DINH"
        elif diem >= nguong_cdd:
            phan_loai = "CDD_TIEU_CHUAN"
            trang_thai = "DA_PHE_DUYET"
        else:
            phan_loai = "CDD_GIAN_LUOC"
            trang_thai = "DA_PHE_DUYET"

        if not ly_do:
            ly_do = ["Không phát hiện yếu tố rủi ro đặc biệt"]

        return diem, phan_loai, trang_thai, ly_do

    def them_ho_so(self, data):
        ma_kh = str(data.get("ma_kh", "")).strip().upper()
        ho_ten = str(data.get("ho_ten", "")).strip().upper()
        if not ma_kh or not ho_ten:
            return False, "Lỗi CIP: Mã khách hàng và Họ tên không được để trống!"
        if ma_kh in self.ho_so_dict:
            return False, f"Lỗi: Mã khách hàng {ma_kh} đã tồn tại!"

        ho_so = {
            "ma_kh": ma_kh,
            "ho_ten": ho_ten,
            "loai_kh": data.get("loai_kh", "Ca_nhan"),
            "quoc_tich": str(data.get("quoc_tich", "VN")).strip().upper(),
            "nganh_nghe": data.get("nganh_nghe", "Giao_duc"),
            "la_pep": bool(data.get("la_pep", False)),
            "cau_truc_phuc_tap": bool(data.get("cau_truc_phuc_tap", False)),
            "giao_dich_du_kien": float(data.get("giao_dich_du_kien", 0)),
        }
        if ho_so["giao_dich_du_kien"] < 0:
            return False, "Lỗi CIP: Hạn mức giao dịch dự kiến không được âm!"

        diem, phan_loai, trang_thai, ly_do = self.danh_gia_ho_so(ho_so)
        ho_so.update({
            "diem_rui_ro": diem,
            "phan_loai": phan_loai,
            "trang_thai": trang_thai,
            "ly_do": ly_do,
        })

        conn, _ = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO KhachHang (
                ma_kh, ho_ten, loai_kh, quoc_tich, nganh_nghe,
                la_pep, cau_truc_phuc_tap, giao_dich_du_kien,
                diem_rui_ro, phan_loai, trang_thai, ly_do
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ho_so["ma_kh"], ho_so["ho_ten"], ho_so["loai_kh"], ho_so["quoc_tich"],
            ho_so["nganh_nghe"], int(ho_so["la_pep"]), int(ho_so["cau_truc_phuc_tap"]),
            ho_so["giao_dich_du_kien"], diem, phan_loai, trang_thai, "; ".join(ly_do)
        ))
        conn.commit()
        conn.close()

        self.ho_so_dict[ma_kh] = ho_so
        if phan_loai == "EDD":
            self.thu_tu_nhap += 1
            heapq.heappush(self.edd_heap, (-diem, self.thu_tu_nhap, ma_kh))

        return True, f"Đã lưu {ma_kh} -> Phân luồng: {phan_loai} ({diem}đ)"

    def cap_nhat_ho_so(self, ma_kh, data):
        ma_kh = ma_kh.strip().upper()
        if ma_kh not in self.ho_so_dict:
            return False, f"Không tìm thấy mã khách hàng {ma_kh}!"

        ho_ten = str(data.get("ho_ten", "")).strip().upper()
        if not ho_ten:
            return False, "Họ tên không được để trống!"

        ho_so = {
            "ma_kh": ma_kh,
            "ho_ten": ho_ten,
            "loai_kh": data.get("loai_kh", "Ca_nhan"),
            "quoc_tich": str(data.get("quoc_tich", "VN")).strip().upper(),
            "nganh_nghe": data.get("nganh_nghe", "Giao_duc"),
            "la_pep": bool(data.get("la_pep", False)),
            "cau_truc_phuc_tap": bool(data.get("cau_truc_phuc_tap", False)),
            "giao_dich_du_kien": float(data.get("giao_dich_du_kien", 0)),
        }
        diem, phan_loai, trang_thai, ly_do = self.danh_gia_ho_so(ho_so)
        if data.get("trang_thai_thu_cong") in {"DA_PHE_DUYET", "DA_TU_CHOI", "CHO_THAM_DINH"}:
            trang_thai = data["trang_thai_thu_cong"]

        ho_so.update({
            "diem_rui_ro": diem,
            "phan_loai": phan_loai,
            "trang_thai": trang_thai,
            "ly_do": ly_do,
        })

        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        now_expr = "GETDATE()" if db_type == "MSSQL" else "CURRENT_TIMESTAMP"
        cursor.execute(f"""
            UPDATE KhachHang
            SET ho_ten=?, loai_kh=?, quoc_tich=?, nganh_nghe=?,
                la_pep=?, cau_truc_phuc_tap=?, giao_dich_du_kien=?,
                diem_rui_ro=?, phan_loai=?, trang_thai=?, ly_do=?,
                ngay_cap_nhat={now_expr}
            WHERE ma_kh=?
        """, (
            ho_so["ho_ten"], ho_so["loai_kh"], ho_so["quoc_tich"], ho_so["nganh_nghe"],
            int(ho_so["la_pep"]), int(ho_so["cau_truc_phuc_tap"]), ho_so["giao_dich_du_kien"],
            diem, phan_loai, trang_thai, "; ".join(ly_do), ma_kh
        ))
        conn.commit()
        conn.close()

        self.ho_so_dict[ma_kh] = ho_so
        if phan_loai == "EDD" and trang_thai == "CHO_THAM_DINH":
            self.thu_tu_nhap += 1
            heapq.heappush(self.edd_heap, (-diem, self.thu_tu_nhap, ma_kh))

        return True, f"Đã cập nhật & tái đánh giá {ma_kh}: {phan_loai} ({diem}đ)"

    def xoa_ho_so(self, ma_kh):
        ma_kh = ma_kh.strip().upper()
        if ma_kh not in self.ho_so_dict:
            return False, "Không tìm thấy hồ sơ!"
        conn, _ = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM KhachHang WHERE ma_kh=?", (ma_kh,))
        conn.commit()
        conn.close()
        del self.ho_so_dict[ma_kh]
        return True, f"Đã xóa hồ sơ {ma_kh} khỏi cơ sở dữ liệu."

    def xu_ly_edd(self, ma_kh, quyet_dinh):
        ma_kh = ma_kh.strip().upper()
        hs = self.ho_so_dict.get(ma_kh)
        if not hs:
            return False, "Không tìm thấy hồ sơ!"

        trang_thai_cu = hs["trang_thai"]
        self.lich_su_stack.append((ma_kh, trang_thai_cu))
        hs["trang_thai"] = quyet_dinh

        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        now_expr = "GETDATE()" if db_type == "MSSQL" else "CURRENT_TIMESTAMP"
        cursor.execute(
            f"UPDATE KhachHang SET trang_thai=?, ngay_cap_nhat={now_expr} WHERE ma_kh=?",
            (quyet_dinh, ma_kh),
        )
        conn.commit()
        conn.close()
        return True, f"Đã chuyển trạng thái {ma_kh} sang {quyet_dinh} (Đã lưu vết Stack)."

    def hoan_tac(self):
        if not self.lich_su_stack:
            return False, "Ngăn xếp lịch sử (Stack) trống, không có thao tác để hoàn tác!"
        ma_kh, trang_thai_cu = self.lich_su_stack.pop()
        if ma_kh not in self.ho_so_dict:
            return False, f"Hồ sơ {ma_kh} không còn tồn tại."

        self.ho_so_dict[ma_kh]["trang_thai"] = trang_thai_cu
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        now_expr = "GETDATE()" if db_type == "MSSQL" else "CURRENT_TIMESTAMP"
        cursor.execute(
            f"UPDATE KhachHang SET trang_thai=?, ngay_cap_nhat={now_expr} WHERE ma_kh=?",
            (trang_thai_cu, ma_kh),
        )
        conn.commit()
        conn.close()

        if trang_thai_cu == "CHO_THAM_DINH":
            self.thu_tu_nhap += 1
            heapq.heappush(
                self.edd_heap,
                (-self.ho_so_dict[ma_kh]["diem_rui_ro"], self.thu_tu_nhap, ma_kh),
            )
        return True, f"Hoàn tác thành công! {ma_kh} đã quay lại trạng thái {trang_thai_cu}."

    def cap_nhat_trong_so_va_tai_danh_gia(self, trong_so_moi):
        conn, _ = get_db_connection()
        cursor = conn.cursor()
        for ma_tc, diem_moi in trong_so_moi.items():
            if ma_tc in self.trong_so:
                self.trong_so[ma_tc]["diem"] = int(diem_moi)
                cursor.execute(
                    "UPDATE CauHinhTrongSo SET diem_trong_so=? WHERE ma_tieu_chi=?",
                    (int(diem_moi), ma_tc),
                )

        for ma_kh, hs in self.ho_so_dict.items():
            diem, phan_loai, _, ly_do = self.danh_gia_ho_so(hs)
            hs["diem_rui_ro"] = diem
            hs["phan_loai"] = phan_loai
            hs["ly_do"] = ly_do
            if phan_loai == "TU_CHOI_CAM_VAN":
                hs["trang_thai"] = "DA_TU_CHOI"
            elif phan_loai == "EDD" and hs["trang_thai"] == "DA_PHE_DUYET":
                hs["trang_thai"] = "CHO_THAM_DINH"
            elif phan_loai != "EDD" and hs["trang_thai"] == "CHO_THAM_DINH":
                hs["trang_thai"] = "DA_PHE_DUYET"

            cursor.execute("""
                UPDATE KhachHang
                SET diem_rui_ro=?, phan_loai=?, trang_thai=?, ly_do=?
                WHERE ma_kh=?
            """, (diem, phan_loai, hs["trang_thai"], "; ".join(ly_do), ma_kh))

        conn.commit()
        conn.close()
        self.tai_du_lieu_tu_db()
        return True, "Đã lưu trọng số mới và tái đánh giá toàn bộ danh mục!"

    def nap_du_lieu_mau_100(self):
        ho = ["NGUYEN", "TRAN", "LE", "PHAM", "HOANG", "VU", "DANG", "BUI"]
        ten = ["AN", "BINH", "CUONG", "DUNG", "GIANG", "HUONG", "KHANH", "MINH", "PHUONG", "TRANG"]
        loai_list = ["Ca_nhan", "Doanh_nghiep", "NGO", "Nuoc_ngoai"]
        qt_list = ["VN", "VN", "VN", "US", "SG", "JP", "IR", "MM", "SY"]
        nganh_list = ["Giao_duc", "Y_te", "Ban_le", "Cong_nghe", "Crypto", "Thuong_mai_QT", "Kim_loai_quy"]

        dem = 0
        ds_bl = list(self.blacklist_set)[:3]
        for i, name in enumerate(ds_bl, 1):
            ok, _ = self.them_ho_so({
                "ma_kh": f"KH{i:03d}", "ho_ten": name, "loai_kh": "Ca_nhan",
                "quoc_tich": "IR", "nganh_nghe": "Tu_do", "la_pep": True,
                "cau_truc_phuc_tap": False, "giao_dich_du_kien": 5000.0
            })
            if ok:
                dem += 1

        for i in range(4, 101):
            ok, _ = self.them_ho_so({
                "ma_kh": f"KH{i:03d}",
                "ho_ten": f"{random.choice(ho)} VAN {random.choice(ten)} {i}",
                "loai_kh": random.choice(loai_list),
                "quoc_tich": random.choice(qt_list),
                "nganh_nghe": random.choice(nganh_list),
                "la_pep": random.random() < 0.15,
                "cau_truc_phuc_tap": random.random() < 0.15,
                "giao_dich_du_kien": round(random.uniform(50, 3000), 1),
            })
            if ok:
                dem += 1
        return True, f"Đã sinh và lưu mới {dem} hồ sơ mẫu vào cơ sở dữ liệu!"


he_thong = HeThongKYCAMLWeb()


# ==============================================================================
# 3. CÁC ĐỊNH TUYẾN WEB & REST API
# ==============================================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tong-quan", methods=["GET"])
def api_tong_quan():
    ds = list(he_thong.ho_so_dict.values())
    tk = {"TU_CHOI_CAM_VAN": 0, "EDD": 0, "CDD_TIEU_CHUAN": 0, "CDD_GIAN_LUOC": 0}
    cho_edd = 0
    for hs in ds:
        tk[hs["phan_loai"]] = tk.get(hs["phan_loai"], 0) + 1
        if hs["phan_loai"] == "EDD" and hs["trang_thai"] == "CHO_THAM_DINH":
            cho_edd += 1

    hang_doi_edd = sorted(
        [hs for hs in ds if hs["phan_loai"] == "EDD" and hs["trang_thai"] == "CHO_THAM_DINH"],
        key=lambda x: x["diem_rui_ro"],
        reverse=True,
    )
    return jsonify({
        "tong_so": len(ds),
        "thong_ke": tk,
        "cho_edd": cho_edd,
        "hang_doi_edd": hang_doi_edd,
        "ho_so": sorted(ds, key=lambda x: x["ma_kh"]),
        "trong_so": he_thong.trong_so,
        "blacklist": sorted(list(he_thong.blacklist_set)),
        "ncct": sorted(list(he_thong.ncct_set)),
        "co_the_undo": len(he_thong.lich_su_stack) > 0,
    })


@app.route("/api/ho-so", methods=["POST"])
def api_them_ho_so():
    ok, msg = he_thong.them_ho_so(request.json)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/ho-so/<ma_kh>", methods=["PUT"])
def api_sua_ho_so(ma_kh):
    ok, msg = he_thong.cap_nhat_ho_so(ma_kh, request.json)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/ho-so/<ma_kh>", methods=["DELETE"])
def api_xoa_ho_so(ma_kh):
    ok, msg = he_thong.xoa_ho_so(ma_kh)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/edd/xu-ly", methods=["POST"])
def api_xu_ly_edd():
    data = request.json
    ok, msg = he_thong.xu_ly_edd(data["ma_kh"], data["quyet_dinh"])
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/edd/undo", methods=["POST"])
def api_undo():
    ok, msg = he_thong.hoan_tac()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/trong-so", methods=["POST"])
def api_cap_nhat_trong_so():
    ok, msg = he_thong.cap_nhat_trong_so_va_tai_danh_gia(request.json)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/danh-muc", methods=["POST"])
def api_cap_nhat_danh_muc():
    data = request.json
    loai = data.get("loai")
    gia_tri = str(data.get("gia_tri", "")).strip().upper()
    hanh_dong = data.get("hanh_dong")
    if not gia_tri:
        return jsonify({"ok": False, "message": "Giá trị không được rỗng!"})

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    if loai == "BLACKLIST":
        if hanh_dong == "THEM":
            if db_type == "MSSQL":
                cursor.execute(
                    "IF NOT EXISTS (SELECT 1 FROM BlacklistSanctions WHERE ho_ten=?) "
                    "INSERT INTO BlacklistSanctions (ho_ten) VALUES (?)",
                    (gia_tri, gia_tri),
                )
            else:
                cursor.execute(
                    "INSERT OR IGNORE INTO BlacklistSanctions (ho_ten) VALUES (?)",
                    (gia_tri,),
                )
        else:
            cursor.execute("DELETE FROM BlacklistSanctions WHERE ho_ten=?", (gia_tri,))
    elif loai == "NCCT":
        if hanh_dong == "THEM":
            if db_type == "MSSQL":
                cursor.execute(
                    "IF NOT EXISTS (SELECT 1 FROM QuocGiaNCCT WHERE ma_quoc_gia=?) "
                    "INSERT INTO QuocGiaNCCT (ma_quoc_gia, ten_quoc_gia, phan_nhom_fatf) VALUES (?, ?, ?)",
                    (gia_tri, gia_tri, gia_tri, "Bổ sung thủ công"),
                )
            else:
                cursor.execute(
                    "INSERT OR IGNORE INTO QuocGiaNCCT (ma_quoc_gia, ten_quoc_gia, phan_nhom_fatf) VALUES (?, ?, ?)",
                    (gia_tri, gia_tri, "Bổ sung thủ công"),
                )
        else:
            cursor.execute("DELETE FROM QuocGiaNCCT WHERE ma_quoc_gia=?", (gia_tri,))
    conn.commit()
    conn.close()
    he_thong.tai_du_lieu_tu_db()
    return jsonify({"ok": True, "message": f"Đã cập nhật danh mục {loai}: {gia_tri}"})


@app.route("/api/nap-mau", methods=["POST"])
def api_nap_mau():
    ok, msg = he_thong.nap_du_lieu_mau_100()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/xuat-csv", methods=["GET"])
def api_xuat_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ma_kh", "ho_ten", "loai_kh", "quoc_tich", "nganh_nghe",
        "la_pep", "cau_truc_phuc_tap", "giao_dich_du_kien",
        "diem_rui_ro", "phan_loai", "trang_thai", "ly_do"
    ])
    for hs in sorted(he_thong.ho_so_dict.values(), key=lambda x: x["ma_kh"]):
        writer.writerow([
            hs["ma_kh"], hs["ho_ten"], hs["loai_kh"], hs["quoc_tich"],
            hs["nganh_nghe"], hs["la_pep"], hs["cau_truc_phuc_tap"],
            hs["giao_dich_du_kien"], hs["diem_rui_ro"], hs["phan_loai"],
            hs["trang_thai"], "; ".join(hs["ly_do"])
        ])
    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=ket_qua_kyc_aml_cloud.csv"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)