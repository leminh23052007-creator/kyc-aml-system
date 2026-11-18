import pyodbc

drivers = [d for d in pyodbc.drivers() if 'SQL Server' in d]
print("Cac ODBC Driver co san:", drivers)

driver_name = drivers[-1] if drivers else "SQL Server"
conn_str = (
    f"DRIVER={{{driver_name}}};"
    r"SERVER=.\SQLEXPRESS;"
    "DATABASE=KYC_AML_DB;"
    "Trusted_Connection=yes;"
    "TrustServerCertificate=yes;"
)

try:
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM CauHinhTrongSo")
    so_dong = cursor.fetchone()[0]
    print(f"KET NOI THANH CONG! So dong trong bang CauHinhTrongSo: {so_dong}")
    conn.close()
except Exception as e:
    print("LOI KET NOI:", e)