import subprocess
import os


def run(cmd):
    subprocess.Popen(cmd, shell=True)
    os.system(cmd)


def query(sql, cursor):
    cursor.execute("SELECT * FROM users WHERE id = " + sql)
