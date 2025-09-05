# logger.py
import logging
from datetime import datetime
import os

LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def setup_logger(name, log_file, level=logging.DEBUG):
    """
    指定された名前、ログファイル、レベルでロガーを設定します。
    複数回呼び出されても、重複してハンドラが追加されないように修正。
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 既にハンドラが設定されている場合は、追加しない
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # ファイルハンドラ
        file_handler = logging.FileHandler(os.path.join(LOG_DIR, log_file), encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # コンソールハンドラ（メインプロセスのログ用）
        if name == "console_log" or name == "detector_log": # コンソールにはメインと検出器のログのみ出力
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            
    return logger

def log_detection(detection_info):
    """
    検出情報を専用のログファイルに記録します。
    新しいプロセス情報も記録するように拡張。
    """
    detection_logger = setup_logger("detection_log", "detections.log")
    
    detection_logger.info(f"検出タイプ: {detection_info['type']}")
    detection_logger.info(f"   ファイル: {detection_info['file']}")
    detection_logger.info(f"   プロセス: PID={detection_info['process_pid']} ({detection_info['process_name']})")
    
    # 新しい情報をログに追加
    if 'exe_path' in detection_info and detection_info['exe_path'] != "N/A":
        detection_logger.info(f"   実行パス: {detection_info['exe_path']}")
    if 'parent_name' in detection_info and detection_info['parent_name'] != "N/A":
        detection_logger.info(f"   親プロセス: {detection_info['parent_name']}")
    if 'cmdline' in detection_info and detection_info['cmdline']:
        detection_logger.info(f"   コマンドライン: {detection_info['cmdline']}")
        
    detection_logger.info(f"   詳細: {detection_info['details']}")
    detection_logger.info(f"   タイムスタンプ: {detection_info['timestamp']}")
    detection_logger.info("-" * 50) # 区切り線で読みやすく