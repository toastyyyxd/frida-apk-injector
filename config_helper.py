import os, json
from types import SimpleNamespace

class KeyStoreConfig(SimpleNamespace):
    debug: bool
    path: str
    password: str
    key_password: str
    alias: str
class BuildConfig(SimpleNamespace):
    allow_proxy: bool
    keystore: KeyStoreConfig
class DownloadConfig(SimpleNamespace):
    package_name: str
    last_version_name: str
    last_version_code: int
class Config(SimpleNamespace):
    build_config: BuildConfig
    download_config: DownloadConfig

def create_default():
    with open('./config.json', 'w') as f:
        json.dump({
            "build_config": {
                "allow_proxy": False,
                "keystore": {
                    "debug": True,
                    "path": "",
                    "password": "",
                    "key_password": "",
                    "alias": ""
                }
            },
            "download_config": {
                "package_name": "",
                "last_version_name": "",
                "last_version_code": -1
            }
        }, f, indent=4)

def open_config():
    if not os.path.exists('./config.json'):
        print('No configuration file, creating default')
        create_default()
    with open('./config.json', 'r') as f:
        config: Config = json.load(f, object_hook=lambda d: SimpleNamespace(**d))
    return config

def write_config(config: Config):
    with open('./config.json', 'w') as f:
        json.dump(to_dict(config), f, indent=4)

def to_dict(item):
    match item:
        case dict():
            data = {}
            for k, v in item.items():
                data[k] = to_dict(v)
            return data
        case list() | tuple():
            return [to_dict(x) for x in item]
        case object(__dict__=_):
            data = {}
            for k, v in item.__dict__.items():
                if not k.startswith("_"):
                    data[k] = to_dict(v)
            return data
        case _:
            return item