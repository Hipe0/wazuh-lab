#!/usr/bin/env python3
# Gui alert Wazuh vao chat/group Telegram qua Bot API (api.telegram.org).
# integratord goi: custom-telegram <alert_file> <api_key=chat_id> <hook_url=https://api.telegram.org>
# Telegram cung kieu API voi Zalo (/bot<token>/sendMessage, JSON {chat_id, text}, tra {ok, description})
# nen dung lai custom-zalo.py, chi doi file token va gioi han do dai tin.
import importlib.util
import os

_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom-zalo.py")
_spec = importlib.util.spec_from_file_location("custom_zalo", _path)
zalo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zalo)

if __name__ == "__main__":
    zalo.main(service="Telegram", token_file="/run/secrets/telegram_token", max_text=4096)
