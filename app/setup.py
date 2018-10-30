from cx_Freeze import setup, Executable
import os, sys

build_exe_options = {
    'packages': [
        'asyncio',
        'base64',
        'binascii',
        '_cffi_backend',
        'cryptography',
        'flask',
        'flask_jwt_extended',
        'flask_sqlalchemy',
        'jinja2',
        'idna',
        'numpy',
        'os',
        'pandas',
        'passlib',
        'sqlalchemy',
        'sys',
        'threading',
        'time',
        'webbrowser',
    ],
    'include_files': [
        os.path.join(sys.base_prefix, 'DLLs', 'sqlite3.dll'),
        'templates/', 'static/'
    ]
}

os.environ['TCL_LIBRARY'] = "C:\\Program Files\\Python35\\tcl\\tcl8.6"
os.environ['TK_LIBRARY'] = "C:\\Program Files\\Python35\\tcl\\tk8.6"

setup(
    name='app',
    version = '0.01',
    options = {'build_exe': build_exe_options},
    executables = [Executable('app.py')]
)