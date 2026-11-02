#!/usr/bin/env python3
# Gui alert Wazuh vao chat/group Telegram qua Bot API (api.telegram.org).
# integratord goi: custom-telegram <alert_file> <api_key=chat_id> <hook_url=https://api.telegram.org>
# Telegram cung kieu API voi Zalo (/bot<token>/sendMessage, JSON {chat_id, text}, tra {ok, description})
# nen dung lai custom-zalo.py, chi doi file token, gioi han do dai tin va them topic.
#
# Group bat Topics: alert duoc gui vao topic theo tactic MITRE (rule.mitre.tactic) qua
# message_thread_id. Bang tactic -> thread id do setup.sh ghi tu TELEGRAM_TOPICS trong .env.
# Alert khong co tactic, hoac tactic khong co trong bang, vao topic General.
import importlib.util
import json
import os

TOPICS_FILE = "/run/secrets/telegram_topics.json"

_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom-zalo.py")
_spec = importlib.util.spec_from_file_location("custom_zalo", _path)
zalo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zalo)


def load_topics():
    try:
        with open(TOPICS_FILE) as f:
            return {k.strip().lower(): int(v) for k, v in json.load(f).items()}
    except (OSError, ValueError, AttributeError):
        return {}


def topic_for(alert):
    topics = load_topics()
    # 1 technique co the thuoc nhieu tactic (vd T1053: Execution, Persistence, Privilege Escalation):
    # lay tactic dau tien co topic
    for tactic in zalo.get(alert, "rule.mitre.tactic") or []:
        thread = topics.get(str(tactic).lower())
        if thread:
            return {"message_thread_id": thread}
    return {}


if __name__ == "__main__":
    zalo.main(service="Telegram", token_file="/run/secrets/telegram_token", max_text=4096, extra=topic_for)
