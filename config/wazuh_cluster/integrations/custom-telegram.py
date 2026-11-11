#!/usr/bin/env python3
# Gui alert Wazuh vao chat/group Telegram qua Bot API (api.telegram.org).
# integratord goi: custom-telegram <alert_file> <api_key=chat_id> <hook_url=https://api.telegram.org>
# Telegram cung kieu API voi Zalo (/bot<token>/sendMessage, JSON {chat_id, text}, tra {ok, description})
# nen dung lai custom-zalo.py, chi doi file token, gioi han do dai tin va them topic.
#
# Group bat Topics: alert duoc gui vao topic theo tactic MITRE (rule.mitre.tactic) qua
# message_thread_id. Bang tactic -> thread id do setup.sh ghi tu TELEGRAM_TOPICS trong .env.
# Alert khong co tactic, hoac tactic khong co trong bang, vao topic General.
#
# Moi group mot bang topic rieng (TELEGRAM_TOPICS cho group chinh, TELEGRAM2_TOPICS cho group thu hai):
# setup.sh ghi {"<chat id>": {"<tactic hoac rule group>": thread_id}}. Khoa trung voi rule.groups
# (vd "dacn_ml") duoc uu tien hon tactic, de alert model ML vao topic rieng. Chat khong co bang -> khong
# gui message_thread_id (group khong bat Topics se loi "message thread not found").
import importlib.util
import json
import os
import sys

TOPICS_FILE = "/run/secrets/telegram_topics.json"

_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom-zalo.py")
_spec = importlib.util.spec_from_file_location("custom_zalo", _path)
zalo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zalo)


def load_topics():
    try:
        with open(TOPICS_FILE) as f:
            data = json.load(f)
        chat = sys.argv[2].strip() if len(sys.argv) > 2 else ""
        if any(isinstance(v, dict) for v in data.values()):
            data = data.get(chat, {})
        # file cu dang phang {"tactic": id}: ap cho moi chat nhu truoc
        return {k.strip().lower(): int(v) for k, v in data.items()}
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def topic_for(alert):
    topics = load_topics()
    if not topics:
        return {}
    # rule group truoc (vd dacn_ml -> topic ML), roi den tactic MITRE
    keys = list(zalo.get(alert, "rule.groups") or [])
    # 1 technique co the thuoc nhieu tactic (vd T1053: Execution, Persistence, Privilege Escalation):
    # lay tactic dau tien co topic
    keys += list(zalo.get(alert, "rule.mitre.tactic") or [])
    for key in keys:
        thread = topics.get(str(key).lower())
        if thread:
            return {"message_thread_id": thread}
    return {}


if __name__ == "__main__":
    zalo.main(service="Telegram", token_file="/run/secrets/telegram_token", max_text=4096, extra=topic_for)
