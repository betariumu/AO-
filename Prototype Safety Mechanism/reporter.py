# reporter.py

import os
import re
from collections import defaultdict
from datetime import datetime

# ログファイルのパス
LOG_FILE = "logs/detections.log"
REPORT_DIR = "reports"

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

def generate_daily_report():
    """
    検出ログを解析し、日次サマリーレポートを生成する
    """
    if not os.path.exists(LOG_FILE):
        print(f"警告: ログファイルが見つかりません: {LOG_FILE}")
        return

    # 今日の日付を取得
    today_date_str = datetime.now().strftime("%Y-%m-%d")
    report_file_path = os.path.join(REPORT_DIR, f"report_{today_date_str}.txt")
    
    detection_counts = defaultdict(int)
    total_detections = 0
    
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    # ログを解析
    for line in log_lines:
        if "検出タイプ:" in line:
            total_detections += 1
            # 正規表現で検出タイプを抽出
            match = re.search(r'検出タイプ: (.+)', line)
            if match:
                detection_type = match.group(1).strip()
                detection_counts[detection_type] += 1
                
    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write("=========================================\n")
        f.write(f"     XDRツール 日次レポート - {today_date_str}\n")
        f.write("=========================================\n\n")
        f.write(f"総検出数: {total_detections} 件\n\n")
        f.write("--- 検出タイプ別内訳 ---\n")
        
        if not detection_counts:
            f.write("本日の検出はありませんでした。\n")
        else:
            for d_type, count in detection_counts.items():
                f.write(f"  - {d_type}: {count} 件\n")

    print(f"日次レポートを生成しました: {report_file_path}")

if __name__ == "__main__":
    generate_daily_report()