import os
import time
import json
import psutil
from datetime import datetime
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import subprocess
import pefile
import logging
import hashlib
import ctypes
import math
import sys
import aiohttp
import asyncio

try:
    from logger import setup_logger
    detector_logger = setup_logger("detector_log", "detector.log", level=logging.DEBUG)
    worker_logger = setup_logger("worker_log", "worker.log", level=logging.DEBUG)
    monitor_logger = setup_logger("process_monitor_log", "monitor.log", level=logging.DEBUG)
    detection_logger = setup_logger("detection_log", "detections.log")
except ImportError:
    import logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    detector_logger = logging.getLogger("detector_log")
    worker_logger = logging.getLogger("worker_log")
    monitor_logger = logging.getLogger("process_monitor_log")
    detection_logger = logging.getLogger("detection_log")
    detector_logger.warning("logger.py が見つかりませんでした。組み込みの logging を使用します。")

HEARTBEAT_FILE = "heartbeat.tmp"
HEARTBEAT_INTERVAL = 2
MONITOR_TIMEOUT = 5

# Windows APIの定義 (ctypes)
class HEAPENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32HeapID", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("dwAddress", ctypes.c_ulong),
        ("dwBlockSize", ctypes.c_ulong),
        ("dwReserved", ctypes.c_ulong),
        ("dwRes", ctypes.c_ulong)
    ]
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_ulong),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_char * 260)
    ]
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
Heap32ListFirst = kernel32.Heap32ListFirst
Heap32ListNext = kernel32.Heap32ListNext
HeapWalk = kernel32.HeapWalk
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle
PROCESS_ALL_ACCESS = 0x1FFFFF
PROCESS_SUSPEND_RESUME = 0x0800
THREAD_SUSPEND_RESUME = 0x0002

# グローバルなベースラインデータ
heap_baseline_data = defaultdict(lambda: {'block_sizes': deque(), 'executable_sizes': deque()})
heap_baseline_learning_start_time = defaultdict(float)

class RealtimeDetector:
    def __init__(self, config_file):
        self.config_file = config_file
        self.config = self.load_config()
        self.file_activity_log = defaultdict(deque)
        self.process_baseline_memory = defaultdict(list)
        self.process_last_check = defaultdict(float)
        self.process_memory_learning_period = {}
        self.is_monitoring = True
        self.observer = Observer()
        self.event_handler = FileSystemEventHandler()
        self.event_handler.on_created = self.on_file_created
        self.event_handler.on_deleted = self.on_file_deleted
        self.process_monitor_thread = None
        self.scan_thread = None
        self.heap_monitor_thread = None

    def load_config(self):
        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)
                return config
        except (FileNotFoundError, json.JSONDecodeError):
            detector_logger.warning(f"警告: {self.config_file} が見つからないか、形式が不正です。デフォルト設定を使用します。")
            return {
                "detection_rules": {},
                "detection_thresholds": {
                    "rapid_file_activity": {"count": 10, "time_window": 5},
                    "mass_creation": {"count": 20, "time_window": 10},
                    "mass_deletion": {"count": 15, "time_window": 10},
                    "abnormal_memory_increase": {"min_increase_mb": 50, "time_window_seconds": 10, "min_data_points": 3},
                    "baseline_deviation_factor": 2.0,
                    "baseline_learning_period_seconds": 300,
                    "min_events_for_baseline": 5,
                    "per_process_memory_threshold": 1.5,
                    "per_process_learning_period_seconds": 180,
                    "heap_scan_interval_seconds": 30,
                    "heap_baseline_learning_period_seconds": 3600,
                    "heap_deviation_threshold": 1.5,
                },
                "whitelist": {},
                "ui_settings": {},
                "monitoring_paths": []
            }
            
    def _send_detection_message(self, message):
        """検出メッセージをstdoutに出力してメインプロセスに送信"""
        try:
            sys.stdout.buffer.write((json.dumps({"type": "detection", "data": message}) + "\n").encode('utf-8'))
            sys.stdout.buffer.flush()
        except Exception as e:
            detector_logger.error(f"stdoutへのメッセージ送信失敗: {e}")

    def _send_progress_message(self, progress):
        """進捗メッセージをstdoutに出力してメインプロセスに送信"""
        try:
            sys.stdout.buffer.write((json.dumps({"type": "progress", "data": progress}) + "\n").encode('utf-8'))
            sys.stdout.buffer.flush()
        except Exception as e:
            detector_logger.error(f"stdoutへの進捗送信失敗: {e}")
            
    def _send_summary_message(self, summary_data):
        """スキャンサマリーメッセージをstdoutに出力してメインプロセスに送信"""
        try:
            sys.stdout.buffer.write((json.dumps({"type": "scan_summary", "data": summary_data}) + "\n").encode('utf-8'))
            sys.stdout.buffer.flush()
        except Exception as e:
            detector_logger.error(f"stdoutへのサマリー送信失敗: {e}")
            
    def _quarantine_or_terminate_process(self, pid, action):
        """プロセスを一時停止または強制終了する"""
        try:
            p = psutil.Process(pid)
            if action == "quarantine":
                p.suspend()
                detector_logger.info(f"プロセス {pid} を一時停止しました。")
            elif action == "terminate":
                p.terminate()
                detector_logger.info(f"プロセス {pid} を強制終了しました。")
        except psutil.NoSuchProcess:
            detector_logger.warning(f"プロセス {pid} は存在しません。")
        except psutil.AccessDenied:
            detector_logger.error(f"プロセス {pid} へのアクセスが拒否されました。管理者権限で実行してください。")
        except Exception as e:
            detector_logger.error(f"プロセス操作中にエラーが発生しました: {e}")

    def start_monitoring(self):
        detector_logger.info("XDR監視を開始します。")
        self.is_monitoring = True
        self.process_monitor_thread = threading.Thread(target=self.check_processes_and_memory_thread, daemon=True)
        self.process_monitor_thread.start()
        
        # ヒープメタデータ監視スレッドを追加
        if os.name == 'nt':
            self.heap_monitor_thread = threading.Thread(target=self.heap_metadata_monitor_thread, daemon=True)
            self.heap_monitor_thread.start()

        try:
            for path in self.config.get("monitoring_paths", []):
                if os.path.exists(path):
                    self.observer.schedule(self.event_handler, path, recursive=True)
                else:
                    detector_logger.warning(f"監視パスが見つかりません: {path}")
            self.observer.start()
            
            while True:
                line = sys.stdin.buffer.readline()
                if not line:
                    break
                
                try:
                    command = json.loads(line.decode('utf-8'))
                    if command["type"] == "scan":
                        threading.Thread(target=lambda: asyncio.run(self.start_scan(command["paths"])), daemon=True).start()
                    elif command["type"] in ["quarantine", "terminate"]:
                        threading.Thread(target=self._quarantine_or_terminate_process, args=(command["pid"], command["type"]), daemon=True).start()
                except json.JSONDecodeError as e:
                    detector_logger.error(f"コマンドの解析に失敗しました: {e}")

        except Exception as e:
            detector_logger.error(f"監視中にエラーが発生しました: {e}")
        finally:
            self.is_monitoring = False
            self.observer.stop()
            self.observer.join()
            detector_logger.info("XDR監視を停止しました。")
    
    def is_admin():
        """現在のプロセスが管理者権限で実行されているか確認する"""
        try:
            return ctypes.windll.shell32.IsUserIsAnAdmin()
        except:
            return False

    def detect_suspicious_processes(self, p):
        """個別のプロセスに対して疑わしい振る舞いを検出する"""
        suspicious_names = self.config['detection_rules']['suspicious_processes']
        p_name = p.info['name'].lower()
        p_pid = p.info['pid']

        if p_name in suspicious_names:
            self._send_detection_message({
                "type": "不審なプロセス",
                "details": f"不審なプロセス '{p.info['name']}' (PID: {p_pid}) を検出しました。",
                "process_pid": p_pid,
            })
        
        # 管理者権限チェック
        if os.name == 'nt' and not RealtimeDetector.is_admin():
             try:
                 PROCESS_QUERY_INFORMATION = 0x0400
                 p_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, p_pid)
                 if p_handle:
                     is_elevated = ctypes.c_bool(False)
                     ctypes.windll.advapi32.IsTokenElevated(p_handle, ctypes.byref(is_elevated))
                     if is_elevated:
                         self._send_detection_message({
                             "type": "管理者権限プロセス",
                             "details": f"プロセス '{p.info['name']}' (PID: {p_pid}) が管理者権限で実行されています。",
                             "process_pid": p_pid,
                         })
                     ctypes.windll.kernel32.CloseHandle(p_handle)
             except Exception:
                 pass

    def check_processes_and_memory_thread(self):
        detector_logger.info("プロセス監視スレッドを開始します。")
        while self.is_monitoring:
            current_time = time.time()
            running_processes = {p.pid: p for p in psutil.process_iter(['name', 'exe', 'cmdline', 'pid'])}
            
            for pid, p in running_processes.items():
                if pid == os.getpid():
                    continue
                try:
                    p_name = p.name()
                    mem_info = p.memory_info()
                    current_mem_mb = mem_info.rss / (1024 * 1024)

                    if not self.process_memory_learning_period.get(pid):
                        self.process_memory_learning_period[pid] = current_time
                    learning_period_seconds = self.config['detection_thresholds']['per_process_learning_period_seconds']
                    
                    if current_time - self.process_memory_learning_period[pid] < learning_period_seconds:
                        self.process_baseline_memory[pid].append(current_mem_mb)
                        if len(self.process_baseline_memory[pid]) > 100:
                            self.process_baseline_memory[pid].pop(0)
                    else:
                        if len(self.process_baseline_memory[pid]) > 0:
                            baseline = sum(self.process_baseline_memory[pid]) / len(self.process_baseline_memory[pid])
                            deviation_factor = self.config['detection_thresholds']['per_process_memory_threshold']
                            if current_mem_mb > baseline * deviation_factor:
                                message = {
                                    "type": "プロセスごとのメモリ逸脱",
                                    "details": f"プロセス '{p_name}' (PID: {pid}) のメモリ使用量がベースラインから大きく逸脱しています。",
                                    "process_name": p_name,
                                    "process_pid": pid,
                                    "current_memory": f"{current_mem_mb:.2f} MB",
                                    "baseline": f"{baseline:.2f} MB"
                                }
                                self._send_detection_message(message)
                    
                    self.detect_suspicious_processes(p)
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                    continue
            time.sleep(1)
        detector_logger.info("プロセス監視スレッドを停止します。")
        
    def heap_metadata_monitor_thread(self):
        """ヒープメタデータ監視スレッド (psutil memory_maps版)"""
        detector_logger.info("ヒープメタデータ監視スレッドを開始します。")
        while self.is_monitoring:
            current_time = time.time()
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.info['pid']
                p_name = proc.info['name']
                
                # 自身のプロセスはスキップ
                if pid == os.getpid():
                    continue

                try:
                    # ベースライン学習期間の確認
                    if pid not in heap_baseline_learning_start_time:
                        heap_baseline_learning_start_time[pid] = current_time
                    
                    self._analyze_heap(proc)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    detector_logger.debug(f"ヒープ分析に失敗しました (PID: {pid}, Name: {p_name}): アクセス拒否またはプロセスが存在しません。")
                except Exception as e:
                    detector_logger.debug(f"ヒープ分析に失敗しました (PID: {pid}, Name: {p_name}): {e}")

            time.sleep(self.config['detection_thresholds']['heap_scan_interval_seconds'])
        detector_logger.info("ヒープメタデータ監視スレッドを停止します。")

    def _analyze_heap(self, process):
        """指定されたプロセスのメモリマップを分析する"""
        try:
            maps = process.memory_maps()
            total_block_size = 0
            executable_blocks_size = 0
            
            for m in maps:
                # `size`と`perms`属性の存在をチェックして堅牢性を確保
                if hasattr(m, 'size') and hasattr(m, 'perms'):
                    total_block_size += m.size
                    if 'x' in m.perms:
                        executable_blocks_size += m.size
            
            pid = process.pid
            p_name = process.name()
            
            current_time = time.time()
            learning_period = self.config['detection_thresholds']['heap_baseline_learning_period_seconds']
            
            if current_time - heap_baseline_learning_start_time[pid] < learning_period:
                heap_baseline_data[pid]['block_sizes'].append(total_block_size)
                heap_baseline_data[pid]['executable_sizes'].append(executable_blocks_size)
            else:
                # 異常性検知
                if heap_baseline_data[pid]['block_sizes']:
                    avg_block_size = sum(heap_baseline_data[pid]['block_sizes']) / len(heap_baseline_data[pid]['block_sizes'])
                    deviation_factor = self.config['detection_thresholds']['heap_deviation_threshold']
                    
                    if total_block_size > avg_block_size * deviation_factor:
                        self._send_detection_message({
                            "type": "ヒープメタデータ異常",
                            "details": f"プロセス '{p_name}' (PID: {pid}) が平均を大きく超えるヒープブロックを割り当てています。",
                            "process_pid": pid,
                        })

                if heap_baseline_data[pid]['executable_sizes']:
                    avg_exec_size = sum(heap_baseline_data[pid]['executable_sizes']) / len(heap_baseline_data[pid]['executable_sizes'])
                    deviation_factor = self.config['detection_thresholds']['heap_deviation_threshold']

                    if executable_blocks_size > avg_exec_size * deviation_factor:
                        self._send_detection_message({
                            "type": "ヒープメタデータ異常",
                            "details": f"プロセス '{p_name}' (PID: {pid}) が異常なサイズの実行可能メモリ領域を割り当てています。",
                            "process_pid": pid,
                        })
                        
            # ベースラインデータのサイズ制限
            while len(heap_baseline_data[pid]['block_sizes']) > 100:
                heap_baseline_data[pid]['block_sizes'].popleft()
            while len(heap_baseline_data[pid]['executable_sizes']) > 100:
                heap_baseline_data[pid]['executable_sizes'].popleft()

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            detector_logger.warning(f"プロセス {process.pid} のメモリマップへのアクセスが拒否されました。")
        except Exception as e:
            detector_logger.error(f"メモリマップ分析中に予期せぬエラー: {e}")

    async def start_scan(self, paths):
        """スキャンを実行し、進捗をUIに送信する"""
        detector_logger.info(f"スキャンを開始します: {paths}")
        
        files_to_scan = []
        for path in paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                files_to_scan.append(path)
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        files_to_scan.append(os.path.join(root, file))
        
        total_files = len(files_to_scan)
        threats_found = 0
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_file(session, file_path) for file_path in files_to_scan]
            
            for i, task in enumerate(asyncio.as_completed(tasks)):
                result = await task
                if result:
                    threats_found += 1
                progress = (i + 1) / total_files if total_files > 0 else 1.0
                self._send_progress_message(progress)
            
        summary = {
            "total_scanned_files": total_files,
            "threats_found": threats_found
        }
        self._send_summary_message(summary)
        detector_logger.info("スキャンが完了しました。")
        self._send_progress_message(1.0)
        
    async def check_file(self, session, file_path):
        """個別のファイルを非同期で検査し、脅威が検出されたか返す"""
        is_threat = False
        try:
            if self.detect_file_attributes(file_path):
                is_threat = True
            
            vt_result = await self.check_file_hash_virustotal(session, file_path)
            if vt_result:
                is_threat = True
                
        except Exception as e:
            detector_logger.error(f"ファイル検査中にエラー: {file_path}, {e}")
            return False
        
        return is_threat

    def detect_file_attributes(self, file_path):
        """ファイルの属性や拡張子を検査する"""
        is_threat = False
        filename, file_extension = os.path.splitext(file_path)
        suspicious_extensions = self.config['detection_rules']['ransomware_extensions']
        if file_extension in suspicious_extensions:
            self._send_detection_message({
                "type": "不審なファイル拡張子",
                "details": f"不審な拡張子を持つファイル '{file_path}' を検出しました。"
            })
            is_threat = True
        try:
            if file_path.lower().endswith(('.exe', '.dll')):
                pe = pefile.PE(file_path)
                if not pe.has_valid_dos_header:
                    self._send_detection_message({
                        "type": "不正なPEヘッダ",
                        "details": f"不正なPEヘッダを持つファイル '{file_path}' を検出しました。"
                    })
                    is_threat = True
        except pefile.PEFormatError:
            self._send_detection_message({
                "type": "不正なPEヘッダ",
                "details": f"PEフォーマットエラーのファイル '{file_path}' を検出しました。"
            })
            is_threat = True
        except Exception:
            pass
        return is_threat

    async def check_file_hash_virustotal(self, session, file_path):
        """ファイルのハッシュ値を計算し、VirusTotal APIで照会する"""
        api_key = "b93d4756ac5efdb38b30797e47cd1e156155dc1fbee3f17269d77686de04c4c1"
        
        file_hash = None
        for i in range(5):
            try:
                with open(file_path, "rb") as f:
                    bytes_to_read = f.read()
                    file_hash = hashlib.sha256(bytes_to_read).hexdigest()
                    break
            except (PermissionError, FileNotFoundError, OSError) as e:
                detector_logger.warning(f"ファイル '{file_path}' へのアクセス失敗。リトライ中 ({i+1}/5): {e}")
                await asyncio.sleep(0.5)
            except Exception as e:
                detector_logger.error(f"ファイル読み込み中に予期せぬエラーが発生しました: {e}")
                return False

        if not file_hash:
            detector_logger.error(f"ファイル '{file_path}' の読み込みに失敗しました。スキップします。")
            return False

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                "x-apikey": api_key,
                "Accept": "application/json"
            }
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious_count = last_analysis_stats.get('malicious', 0)
                    
                    if malicious_count > 0:
                        self._send_detection_message({
                            "type": "既知のマルウェア (VirusTotal)",
                            "details": f"ファイル '{file_path}' がVirusTotalで{malicious_count}件のエンジンに悪意があると検出されました。",
                            "process_pid": None
                        })
                        return True
                elif response.status == 404:
                    detector_logger.info(f"ハッシュ {file_hash} はVirusTotalに存在しません。")
                elif response.status == 429:
                    detector_logger.warning("VirusTotal APIのレート制限に達しました。")
                else:
                    detector_logger.error(f"VirusTotal APIへのリクエストに失敗しました。ステータスコード: {response.status}")
        except Exception as e:
            detector_logger.error(f"VirusTotal API呼び出し中にエラーが発生しました: {e}")
        return False

    def on_file_created(self, event):
        if event.is_directory: return
        self.log_file_activity(event.src_path, "creation")
        self.check_mass_activity(event.src_path, "mass_creation")
        self.detect_file_attributes(event.src_path)
        
        threading.Thread(target=lambda: asyncio.run(self.on_file_event_async(event.src_path)), daemon=True).start()

    def on_file_deleted(self, event):
        if event.is_directory: return
        self.log_file_activity(event.src_path, "deletion")
        self.check_mass_activity(event.src_path, "mass_deletion")
        
    async def on_file_event_async(self, file_path):
        async with aiohttp.ClientSession() as session:
            await self.check_file_hash_virustotal(session, file_path)

    def log_file_activity(self, file_path, activity_type):
        current_time = time.time()
        self.file_activity_log[file_path].append(current_time)
        time_window = self.config['detection_thresholds']['rapid_file_activity']['time_window']
        while self.file_activity_log[file_path] and self.file_activity_log[file_path][0] < current_time - time_window:
            self.file_activity_log[file_path].popleft()
            
    def check_mass_activity(self, file_path, activity_type_key):
        count = self.config['detection_thresholds'][activity_type_key]['count']
        time_window = self.config['detection_thresholds'][activity_type_key]['time_window']
        if len(self.file_activity_log[file_path]) >= count:
            message = {
                "type": "一括アクティビティ検出",
                "details": f"ファイル '{file_path}' で不審な一括{activity_type_key}アクティビティを検出しました。",
                "process_pid": None
            }
            self._send_detection_message(message)

def run_heartbeat_monitor(main_script_path):
    monitor_logger.info("監視プロセスを開始しました。メインプロセスのハートビートを監視します。")
    while True:
        try:
            if not os.path.exists(HEARTBEAT_FILE):
                last_heartbeat_time = 0
            else:
                with open(HEARTBEAT_FILE, "r") as f:
                    last_heartbeat_time = float(f.read())
            
            if time.time() - last_heartbeat_time > MONITOR_TIMEOUT:
                status_message = "ハートビートが途絶えました"
                monitor_logger.warning(f"{status_message}。再起動を試みます...")
                try:
                    subprocess_cmd = [sys.executable, main_script_path]
                    
                    if os.name == 'nt':
                        subprocess.Popen(subprocess_cmd, creationflags=subprocess.DETACHED_PROCESS, close_fds=True)
                    else:
                        subprocess.Popen(subprocess_cmd, preexec_fn=os.setsid, close_fds=True)
                    monitor_logger.info("メインプロセスの再起動を試みました。")
                    break
                except Exception as e:
                    monitor_logger.error(f"メインプロセスの再起動に失敗しました: {e}", exc_info=True)
            time.sleep(1)
        except Exception as e:
            monitor_logger.error(f"ハートビート監視中にエラーが発生しました: {e}", exc_info=True)
            time.sleep(1)

    monitor_logger.info("監視プロセスが停止しました。")
    if os.path.exists(HEARTBEAT_FILE):
        try:
            os.remove(HEARTBEAT_FILE)
        except Exception as e:
            monitor_logger.error(f"ハートビートファイルの削除に失敗しました: {e}")

if __name__ == "__main__":
    if '--child' in sys.argv:
        detector = RealtimeDetector("config.json")
        detector.start_monitoring()
    else:
        main_script_path = os.path.join(os.path.dirname(__file__), "main.py")
        run_heartbeat_monitor(main_script_path)