import flet as ft
import os
import asyncio
import psutil
import time
import json
import subprocess
from flet import Colors, Icons
from plyer import notification
from datetime import datetime
import sys
from flet.matplotlib_chart import MatplotlibChart
import matplotlib.pyplot as plt

# グローバル変数 (Fletアプリとバックエンドの連携用)
detection_message_queue = asyncio.Queue()
system_memory_queue = asyncio.Queue()
detector_process = None
scan_progress_queue = asyncio.Queue()
scan_summary_queue = asyncio.Queue() # スキャンサマリー用キュー

# 各監視タスクのインスタンス
system_memory_monitor_task = None
system_memory_ui_update_task = None
detection_log_update_task = None
scan_progress_ui_update_task = None

# 設定ファイルのパスを定義
CONFIG_FILE = "config.json"

# 通知の冷却期間（秒）
NOTIFICATION_COOLDOWN_SECONDS = 30
last_notification_time = time.time()

def get_or_create_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            if "ui_settings" not in config:
                config["ui_settings"] = {"theme_mode": "system"}
            save_config(config)
            return config
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"警告: {CONFIG_FILE} が見つからないか、形式が不正です。デフォルト設定で作成します。")
        
        user_home = os.path.expanduser('~')
        
        default_config = {
            "detection_rules": {
                "ransomware_extensions": [
                    ".lock",
                    ".encrypted",
                    ".xyz",
                    ".crypt",
                    ".rnsm"
                ],
                "suspicious_processes": [
                    "powershell.exe",
                    "wscript.exe",
                    "cscript.exe"
                ],
                "suspicious_parent_child_relations": {
                    "powershell.exe": [
                        "explorer.exe",
                        "cmd.exe"
                    ],
                    "cmd.exe": [
                        "explorer.exe",
                        "powershell.exe"
                    ]
                },
                "suspicious_cmd_args_keywords": [
                    "-encodedcommand",
                    "iex",
                    "system.net.webclient"
                ],
                "suspicious_exe_path_keywords": [
                    "temp",
                    "appdata\\local\\temp",
                    "programdata",
                    "users\\public",
                    "windows\\temp",
                    "recycle.bin"
                ],
                "living_off_the_land_rules": {
                    "powershell.exe": [
                        "Invoke-Expression",
                        "DownloadString",
                        "DownloadFile",
                        "IEX"
                    ],
                    "cmd.exe": [
                        "certutil.exe -urlcache",
                        "bitsadmin /transfer",
                        "echo"
                    ]
                }
            },
            "detection_thresholds": {
                "rapid_file_activity": {
                    "count": 10,
                    "time_window": 5
                },
                "mass_creation": {
                    "count": 20,
                    "time_window": 10
                },
                "mass_deletion": {
                    "count": 15,
                    "time_window": 10
                },
                "abnormal_memory_increase": {
                    "min_increase_mb": 50,
                    "time_window_seconds": 10,
                    "min_data_points": 3
                },
                "baseline_deviation_factor": 2.0,
                "baseline_learning_period_seconds": 300,
                "min_events_for_baseline": 5,
                "per_process_memory_threshold": 1.5,
                "per_process_learning_period_seconds": 180
            },
            "whitelist": {
                "allowed_exe_paths": [
                    "C:\\Program Files\\",
                    "C:\\Program Files (x86)\\",
                    "C:\\Windows\\",
                    os.path.join(user_home, 'AppData', 'Local', 'Programs', 'Python', 'Python313', 'python.exe'),
                    "C:\\Users\\karew\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\ProgramData\\Lenovo\\Vantage\\Addins\\BatteryWidgetAddin\\3.0.0.163\\BatteryWidgetHost\\BatteryWidgetHost.exe",
                    "C:\\ProgramData\\Lenovo\\Udc\\Hosts\\x64\\AppProvisioningPlugin.exe",
                    "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25070.5-0\\MsMpEng.exe",
                    "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25070.5-0\\NisSrv.exe"
                ],
                "allowed_parent_child_relations": [],
                "allowed_cmd_args": [
                    os.path.join(user_home, 'Documents', 'WindowsPowerShell', 'Modules', 'Pester', '4.10.1', 'Pester.psm1')
                ]
            },
            "monitoring_paths": [
                os.path.join(user_home, 'Documents')
            ],
            "ui_settings": {
                "theme_mode": "system"
            }
        }
        
        save_config(default_config)
        return default_config

def save_config(config):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        print("設定ファイルを保存しました。")
    except Exception as e:
        print(f"設定ファイルの保存に失敗しました: {e}")

async def monitor_system_memory_task():
    """システムメモリ使用率を非同期で監視し、キューに格納する"""
    while True:
        try:
            mem = await asyncio.to_thread(psutil.virtual_memory)
            await system_memory_queue.put(mem)
            await asyncio.sleep(1)
        except Exception:
            continue

async def update_system_memory_ui(page):
    """キューからメモリ情報を取得し、UIを更新する"""
    while True:
        try:
            mem = await system_memory_queue.get()
            system_mem_total.value = f"合計: {mem.total / (1024 ** 3):.2f} GB"
            system_mem_available.value = f"空き: {mem.available / (1024 ** 3):.2f} GB"
            system_mem_percent.value = f"使用率: {mem.percent}%"
            memory_usage_bar.value = mem.percent / 100
            page.update()
            system_memory_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"update_system_memory_uiで予期せぬエラー: {e}")

async def update_detection_log(page):
    """検出ログメッセージを非同期でキューから取得し、UIを更新する"""
    global last_notification_time
    while True:
        try:
            message = await detection_message_queue.get()
            
            if not isinstance(message, dict) or 'data' not in message:
                continue

            message_data = message['data']
            
            log_message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
            details = message_data.get('details', '詳細不明')
            log_message += f" {details}"
            
            proc_name = message_data.get('process_name')
            proc_pid = message_data.get('process_pid')
            
            if proc_name and proc_pid:
                log_message += f" (プロセス: {proc_name}, PID: {proc_pid})"
            
            log_text = ft.Text(log_message)
            
            if message_data.get("type") == "プロセスごとのメモリ逸脱" or message_data.get("type") == "異常なメモリ使用量の検出":
                memory_detection_log_list.controls.insert(0, log_text)
            else:
                detection_log_list.controls.insert(0, log_text)
                
            page.update()
            detection_message_queue.task_done()
            
            current_time = time.time()
            if current_time - last_notification_time >= NOTIFICATION_COOLDOWN_SECONDS:
                notification.notify(
                    title="XDR検出",
                    message=f"不審な活動を検出しました: {details}",
                    app_name="XDR Tool",
                    timeout=10
                )
                last_notification_time = current_time
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"update_detection_logで予期せぬエラー: {e}")

async def update_scan_progress_ui(page):
    """スキャン進捗メッセージを非同期でキューから取得し、UIを更新する"""
    while True:
        try:
            progress = await scan_progress_queue.get()
            scan_progress_bar.value = progress
            scan_progress_text.value = f"スキャン進捗: {progress * 100:.0f}%"
            if progress >= 1.0:
                scan_button_1.disabled = False
                scan_button_2.disabled = False
                scan_button_3.disabled = False
                scan_progress_text.value = "スキャン進捗: 100% (完了)"
            page.update()
            scan_progress_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"update_scan_progress_uiで予期せぬエラー: {e}")
            
async def handle_detector_output(reader, page):
    """非同期で検出器プロセスからの出力を読み取る"""
    while True:
        try:
            line = await reader.readline()
            if not line:
                break
            
            output_data = line.decode('utf-8').strip()
            
            try:
                message = json.loads(output_data)
                message_type = message.get("type")
                
                if message_type == "detection":
                    await detection_message_queue.put(message)
                elif message_type == "progress":
                    await scan_progress_queue.put(message.get("data"))
                elif message_type == "scan_summary":
                    await scan_summary_queue.put(message.get("data"))
                    show_scan_summary_dialog(page, message.get("data"))
            except json.JSONDecodeError:
                print(f"Detector Output: {output_data}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Error reading from detector process: {e}")
            break

def show_scan_summary_dialog(page, summary_data):
    """スキャンサマリーを円グラフで表示するダイアログ"""
    total_files = summary_data.get('total_scanned_files', 0)
    threats = summary_data.get('threats_found', 0)
    clean_files = total_files - threats
    
    labels = ['安全なファイル', '脅威']
    sizes = [clean_files, threats]
    colors = ['#4CAF50', '#F44336']
    
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    
    dialog_content = ft.Column(
        [
            ft.Text("スキャンサマリー", size=20, weight=ft.FontWeight.BOLD),
            ft.Text(f"合計スキャン数: {total_files}"),
            ft.Text(f"検出された脅威数: {threats}"),
            ft.Text(f"安全なファイル数: {clean_files}"),
            ft.Container(
                content=MatplotlibChart(fig),
                width=400,
                height=400,
            ),
            ft.ElevatedButton("閉じる", on_click=lambda e: page.close_dialog()),
        ]
    )
    
    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("スキャン完了！"),
        content=dialog_content,
        on_dismiss=lambda e: print("ダイアログが閉じられました"),
    )
    
    page.dialog = dialog
    page.dialog.open = True
    page.update()

async def handle_scan_button_click(e, scan_type):
    global detector_process
    if not detector_process or detector_process.returncode is not None:
        print("検出器プロセスが実行されていません。")
        return

    if scan_type == "full":
        paths_to_scan = ["C:\\"]
        scan_button_1.disabled = True
    elif scan_type == "partial":
        temp_dir = os.path.join(os.environ['TEMP'])
        paths_to_scan = [temp_dir]
        scan_button_2.disabled = True
    elif scan_type == "specific":
        paths_to_scan = [scan_path_input.value]
        scan_button_3.disabled = True

    scan_progress_bar.value = 0
    scan_progress_text.value = "スキャン進捗: 0%"
    e.page.update()

    command_to_send = {"type": "scan", "paths": paths_to_scan}
    detector_process.stdin.write((json.dumps(command_to_send) + "\n").encode('utf-8'))
    await detector_process.stdin.drain()

async def main(page_main: ft.Page):
    global page, system_mem_total, system_mem_available, system_mem_percent, memory_usage_bar, detection_log_list, memory_detection_log_list
    global scan_button_1, scan_button_2, scan_button_3, scan_path_input, scan_progress_bar, scan_progress_text, detector_process

    page = page_main
    page.title = "XDR Tool"
    
    config = get_or_create_config()
    page.theme_mode = config.get("ui_settings", {}).get("theme_mode", "system")
    page.update()

    async def on_full_scan_click(e):
        await handle_scan_button_click(e, "full")

    async def on_partial_scan_click(e):
        await handle_scan_button_click(e, "partial")

    async def on_specific_scan_click(e):
        await handle_scan_button_click(e, "specific")

    scan_button_1 = ft.ElevatedButton(
        text="全体スキャン (C:\\)",
        icon=Icons.SECURITY,
        on_click=on_full_scan_click,
        bgcolor=Colors.BLUE_600,
        color=Colors.WHITE,
    )
    scan_button_2 = ft.ElevatedButton(
        text="部分的スキャン (一時フォルダ)",
        icon=Icons.FOLDER_OPEN,
        on_click=on_partial_scan_click,
        bgcolor=Colors.BLUE_600,
        color=Colors.WHITE,
    )
    scan_path_input = ft.TextField(label="ファイル/フォルダのパス", width=400)
    scan_button_3 = ft.ElevatedButton(
        text="指定スキャン",
        icon=Icons.FILE_UPLOAD,
        on_click=on_specific_scan_click,
        bgcolor=Colors.BLUE_600,
        color=Colors.WHITE,
    )

    scan_progress_bar = ft.ProgressBar(value=0, color=Colors.CYAN_400)
    scan_progress_text = ft.Text("スキャン進捗: 0%", size=14, weight=ft.FontWeight.BOLD)
    
    system_mem_total = ft.Text("合計: N/A")
    system_mem_available = ft.Text("空き: N/A")
    system_mem_percent = ft.Text("使用率: N/A")
    memory_usage_bar = ft.ProgressBar(value=0, color=Colors.GREEN_400)
    
    detection_log_list = ft.ListView(expand=True, spacing=10, padding=20)
    memory_detection_log_list = ft.ListView(expand=True, spacing=10, padding=20)

    tabs_control = ft.Tabs(
        selected_index=0,
        animation_duration=300,
        tabs=[
            ft.Tab(
                text="コントロール",
                icon=Icons.POWER_SETTINGS_NEW,
                content=ft.Column(
                    [
                        ft.Text("XDR監視コントロール", size=24, weight=ft.FontWeight.BOLD),
                        ft.Text("監視機能は自動で起動し、ハートビートで監視されます。", size=12),
                        ft.Divider(),
                        ft.Text("静的スキャン", size=16, weight=ft.FontWeight.BOLD),
                        scan_button_1,
                        scan_button_2,
                        ft.Row([scan_path_input, scan_button_3], alignment=ft.MainAxisAlignment.CENTER),
                        ft.Container(height=10),
                        scan_progress_text,
                        scan_progress_bar,
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    expand=True,
                ),
            ),
            ft.Tab(
                text="ログ",
                icon=Icons.LIST_ALT,
                content=ft.Column(
                    [
                        ft.Text("検出ログ:", size=14, weight=ft.FontWeight.BOLD),
                        detection_log_list,
                    ],
                    expand=True,
                    horizontal_alignment=ft.CrossAxisAlignment.START,
                ),
            ),
            ft.Tab(
                text="メモリ監視",
                icon=Icons.MEMORY,
                content=ft.Column(
                    [
                        ft.Text("システム全体のメモリ使用率:", size=16, weight=ft.FontWeight.BOLD),
                        ft.Row([system_mem_total, system_mem_available, system_mem_percent], spacing=20),
                        memory_usage_bar,
                        ft.Divider(),
                        ft.Text("メモリ関連の検出ログ:", size=14, weight=ft.FontWeight.BOLD),
                        memory_detection_log_list,
                    ],
                    expand=True,
                    horizontal_alignment=ft.CrossAxisAlignment.START,
                ),
            ),
        ],
        expand=1,
    )

    page.add(tabs_control)
    
    system_memory_monitor_task = asyncio.create_task(monitor_system_memory_task())
    system_memory_ui_update_task = asyncio.create_task(update_system_memory_ui(page))
    detection_log_update_task = asyncio.create_task(update_detection_log(page))
    scan_progress_ui_update_task = asyncio.create_task(update_scan_progress_ui(page))
    
    detector_script_path = os.path.join(os.path.dirname(__file__), "detector.py")
    subprocess_cmd = [sys.executable, detector_script_path, '--child']
    
    detector_process = await asyncio.create_subprocess_exec(
        *subprocess_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE
    )

    asyncio.create_task(handle_detector_output(detector_process.stdout, page))
    
    # アプリケーション終了時にサブプロセスを終了
    def on_page_close(e):
        if detector_process and detector_process.returncode is None:
            detector_process.terminate()
            print("Detector process terminated.")
    page.on_close = on_page_close
    page.update()

if __name__ == "__main__":
    ft.app(target=main)