import ctypes
import sys
import os
import psutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from ctypes import wintypes
import io

# 手动定义LPTHREAD_START_ROUTINE类型
wintypes.LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID)

# 设置中文显示
if sys.stdout is not None:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 加载Windows API函数
def load_windows_apis():
    """加载所需的Windows API函数"""
    kernel32 = ctypes.WinDLL('kernel32.dll')
    
    # 定义函数原型
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    
    kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    
    kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    
    kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CreateRemoteThread.restype = wintypes.HANDLE
    
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    
    kernel32.GetProcAddress.argtypes = [wintypes.HANDLE, wintypes.LPCSTR]
    kernel32.GetProcAddress.restype = wintypes.LPVOID
    
    kernel32.LoadLibraryA.argtypes = [wintypes.LPCSTR]
    kernel32.LoadLibraryA.restype = wintypes.HMODULE
    
    kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
    kernel32.GetModuleHandleA.restype = wintypes.HMODULE
    
    kernel32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.VirtualProtectEx.restype = wintypes.BOOL
    
    # 获取LoadLibraryA函数的地址
    load_library_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b'kernel32.dll'), b'LoadLibraryA')
    
    return kernel32, load_library_addr

class DLLInjector:
    """DLL注入工具类，支持多种注入方法"""
    
    def __init__(self, logger=None):
        """初始化注入器"""
        self.kernel32, self.load_library_addr = load_windows_apis()
        self.PROCESS_ALL_ACCESS = 0x1F0FFF
        self.MEM_COMMIT = 0x1000
        self.MEM_RESERVE = 0x2000
        self.PAGE_READWRITE = 0x04
        self.PAGE_EXECUTE_READWRITE = 0x40
        self.INFINITE = 0xFFFFFFFF
        self.logger = logger or self._default_logger
    
    def _default_logger(self, message):
        """默认的日志记录函数"""
        print(message)
    
    def log(self, message):
        """记录日志信息"""
        if callable(self.logger):
            self.logger(message)
    
    def get_process_handle(self, pid):
        """获取指定进程的句柄"""
        try:
            h_process = self.kernel32.OpenProcess(
                self.PROCESS_ALL_ACCESS,
                False,
                pid
            )
            if not h_process:
                self.log(f"无法打开进程 {pid}，错误码: {ctypes.get_last_error()}")
                return None
            self.log(f"成功打开进程 {pid}")
            return h_process
        except Exception as e:
            self.log(f"获取进程句柄时出错: {str(e)}")
            return None
    
    def inject_dll(self, pid, dll_path):
        """常规DLL注入方法（使用LoadLibraryA）"""
        try:
            # 确保DLL文件存在
            if not os.path.exists(dll_path):
                self.log(f"DLL文件不存在: {dll_path}")
                return False
            
            # 获取DLL的绝对路径
            dll_path = os.path.abspath(dll_path)
            dll_path_bytes = dll_path.encode('utf-8')
            
            self.log(f"准备注入DLL: {dll_path} 到进程ID: {pid}")
            
            # 打开目标进程
            h_process = self.get_process_handle(pid)
            if not h_process:
                return False
            
            try:
                # 在目标进程中分配内存以存储DLL路径
                dll_path_addr = self.kernel32.VirtualAllocEx(
                    h_process,
                    None,
                    len(dll_path_bytes) + 1,  # +1 用于存储终止符
                    self.MEM_COMMIT | self.MEM_RESERVE,
                    self.PAGE_READWRITE
                )
                
                if not dll_path_addr:
                    self.log(f"无法在目标进程中分配内存，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功在目标进程中分配内存，地址: 0x{dll_path_addr:x}")
                
                # 向目标进程写入DLL路径
                bytes_written = wintypes.DWORD(0)
                if not self.kernel32.WriteProcessMemory(
                    h_process,
                    dll_path_addr,
                    dll_path_bytes,
                    len(dll_path_bytes) + 1,
                    ctypes.byref(bytes_written)
                ):
                    self.log(f"无法写入DLL路径到目标进程，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功写入DLL路径到目标进程，写入字节数: {bytes_written.value}")
                
                # 创建远程线程来调用LoadLibraryA加载DLL
                h_thread = self.kernel32.CreateRemoteThread(
                    h_process,
                    None,
                    0,
                    ctypes.cast(self.load_library_addr, wintypes.LPTHREAD_START_ROUTINE),
                    dll_path_addr,
                    0,
                    None
                )
                
                if not h_thread:
                    self.log(f"无法创建远程线程，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功创建远程线程，线程句柄: {h_thread}")
                
                # 等待远程线程完成
                self.kernel32.WaitForSingleObject(h_thread, self.INFINITE)
                
                self.log(f"DLL注入成功! 进程ID: {pid}, DLL路径: {dll_path}")
                return True
                
            finally:
                # 清理资源
                if h_process:
                    self.kernel32.CloseHandle(h_process)
                if 'h_thread' in locals() and h_thread:
                    self.kernel32.CloseHandle(h_thread)
                    
        except Exception as e:
            self.log(f"常规DLL注入时出错: {str(e)}")
            return False
    
    def reflective_dll_inject(self, pid, dll_path):
        """反射式DLL注入方法"""
        try:
            # 确保DLL文件存在
            if not os.path.exists(dll_path):
                self.log(f"DLL文件不存在: {dll_path}")
                return False
            
            # 读取DLL文件内容
            with open(dll_path, 'rb') as f:
                dll_data = f.read()
            
            self.log(f"准备反射式注入DLL: {dll_path} 到进程ID: {pid}")
            self.log(f"DLL文件大小: {len(dll_data)} 字节")
            
            # 打开目标进程
            h_process = self.get_process_handle(pid)
            if not h_process:
                return False
            
            try:
                # 在目标进程中分配内存以存储DLL内容
                dll_base = self.kernel32.VirtualAllocEx(
                    h_process,
                    None,
                    len(dll_data),
                    self.MEM_COMMIT | self.MEM_RESERVE,
                    self.PAGE_READWRITE
                )
                
                if not dll_base:
                    self.log(f"无法在目标进程中分配内存，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功在目标进程中分配内存，基地址: 0x{dll_base:x}")
                
                # 向目标进程写入DLL内容
                bytes_written = wintypes.DWORD(0)
                if not self.kernel32.WriteProcessMemory(
                    h_process,
                    dll_base,
                    dll_data,
                    len(dll_data),
                    ctypes.byref(bytes_written)
                ):
                    self.log(f"无法写入DLL内容到目标进程，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功写入DLL内容到目标进程，写入字节数: {bytes_written.value}")
                
                # 尝试解析PE头以找到真实入口点（如果DLL是标准PE格式）
                entry_point = dll_base
                try:
                    # 检查DOS头签名
                    if len(dll_data) > 64 and dll_data[0:2] == b'MZ':
                        # 获取PE头偏移量
                        e_lfanew = int.from_bytes(dll_data[0x3C:0x40], byteorder='little')
                        # 检查PE签名
                        if len(dll_data) > e_lfanew + 4 and dll_data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                            # 获取可选头偏移量
                            optional_header_offset = e_lfanew + 24
                            # 获取入口点RVA
                            entry_point_rva = int.from_bytes(dll_data[optional_header_offset + 16:optional_header_offset + 20], byteorder='little')
                            # 计算真实入口点
                            if entry_point_rva > 0:
                                entry_point = ctypes.c_void_p(dll_base + entry_point_rva)
                                self.log(f"成功解析PE头，找到入口点RVA: 0x{entry_point_rva:x}")
                except Exception as pe_err:
                    self.log(f"解析PE头时出错，将使用DLL基址作为入口点: {str(pe_err)}")
                
                # 更改内存保护属性为可执行
                old_protection = wintypes.DWORD(0)
                if not self.kernel32.VirtualProtectEx(
                    h_process,
                    dll_base,
                    len(dll_data),
                    self.PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protection)
                ):
                    self.log(f"无法更改内存保护属性，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功更改内存保护属性为可执行")
                
                self.log(f"准备执行DLL，入口点地址: 0x{entry_point.value:x}")
                
                # 创建远程线程来执行DLL
                h_thread = self.kernel32.CreateRemoteThread(
                    h_process,
                    None,
                    0,
                    ctypes.cast(entry_point, wintypes.LPTHREAD_START_ROUTINE),
                    None,
                    0,
                    None
                )
                
                if not h_thread:
                    self.log(f"无法创建远程线程，错误码: {ctypes.get_last_error()}")
                    return False
                
                self.log(f"成功创建远程线程，线程句柄: {h_thread}")
                
                # 等待远程线程完成
                self.kernel32.WaitForSingleObject(h_thread, self.INFINITE)
                
                self.log(f"反射式DLL注入成功! 进程ID: {pid}, DLL路径: {dll_path}")
                return True
                
            finally:
                # 清理资源
                if h_process:
                    self.kernel32.CloseHandle(h_process)
                if 'h_thread' in locals() and h_thread:
                    self.kernel32.CloseHandle(h_thread)
                    
        except Exception as e:
            self.log(f"反射式DLL注入时出错: {str(e)}")
            return False
    
    def create_thread_injection(self, pid, dll_path):
        """CreateThread注入方法（与常规注入类似，但提供更详细的日志）"""
        return self.inject_dll(pid, dll_path)
    
    def nt_create_thread_ex_injection(self, pid, dll_path):
        """NtCreateThreadEx注入方法（未完全实现，当前使用CreateRemoteThread替代）"""
        self.log("注意: NtCreateThreadEx注入方法当前使用CreateRemoteThread替代实现")
        return self.inject_dll(pid, dll_path)

class DLLInjectorGUI:
    """DLL注入工具的图形界面类"""
    
    def __init__(self, root):
        """初始化GUI界面"""
        self.root = root
        self.root.title("DLL注入工具")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 设置中文字体
        self.style = ttk.Style()
        self.style.configure("Treeview.Heading", font=("SimHei", 10, "bold"))
        self.style.configure("Treeview", font=("SimHei", 10))
        
        # 初始化注入器
        self.injector = DLLInjector(logger=self.log_message)
        
        # 创建界面元素
        self.create_widgets()
        
        # 刷新进程列表
        self.refresh_process_list()
    
    def create_widgets(self):
        """创建GUI界面元素"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 进程列表区域
        process_frame = ttk.LabelFrame(main_frame, text="运行中的进程", padding="10")
        process_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 进程列表树状视图
        columns = ("pid", "name", "cpu", "memory")
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show="headings")
        
        # 设置列标题和宽度
        self.process_tree.heading("pid", text="进程ID")
        self.process_tree.heading("name", text="进程名称")
        self.process_tree.heading("cpu", text="CPU使用率")
        self.process_tree.heading("memory", text="内存使用")
        
        self.process_tree.column("pid", width=80, anchor=tk.CENTER)
        self.process_tree.column("name", width=200, anchor=tk.W)
        self.process_tree.column("cpu", width=100, anchor=tk.CENTER)
        self.process_tree.column("memory", width=120, anchor=tk.CENTER)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        # 放置进程列表和滚动条
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 刷新按钮
        refresh_button = ttk.Button(process_frame, text="刷新列表", command=self.refresh_process_list)
        refresh_button.pack(pady=5, fill=tk.X)
        
        # DLL选择和注入设置区域
        settings_frame = ttk.LabelFrame(main_frame, text="注入设置", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        
        # DLL文件选择
        dll_frame = ttk.Frame(settings_frame)
        dll_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(dll_frame, text="DLL文件:", width=10).pack(side=tk.LEFT)
        
        self.dll_path_var = tk.StringVar()
        dll_entry = ttk.Entry(dll_frame, textvariable=self.dll_path_var)
        dll_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        
        browse_button = ttk.Button(dll_frame, text="浏览...", command=self.browse_dll_file)
        browse_button.pack(side=tk.RIGHT)
        
        # 注入方法选择
        method_frame = ttk.Frame(settings_frame)
        method_frame.pack(fill=tk.X)
        
        ttk.Label(method_frame, text="注入方法:", width=10).pack(side=tk.LEFT)
        
        self.injection_method_var = tk.StringVar(value="常规注入")
        method_combobox = ttk.Combobox(method_frame, textvariable=self.injection_method_var, state="readonly")
        method_combobox['values'] = ("常规注入", "反射式注入", "CreateThread注入", "NtCreateThreadEx注入")
        method_combobox.pack(side=tk.LEFT, padx=(5, 5))
        
        # 注入按钮
        inject_button = ttk.Button(settings_frame, text="注入DLL", command=self.inject_dll, style="Accent.TButton")
        inject_button.pack(pady=10, fill=tk.X)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("SimHei", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # 设置按钮样式
        self.style.configure("Accent.TButton", foreground="red", font=("SimHei", 10, "bold"))
    

            
    def refresh_process_list(self):
        """刷新进程列表"""
        # 清空现有列表
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        try:
            # 获取所有进程并添加到列表
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    cpu_percent = f"{proc.info['cpu_percent']}%"
                    memory_percent = f"{proc.info['memory_percent']:.2f}%"
                    
                    # 直接添加进程信息，不显示图标
                    self.process_tree.insert("", tk.END, values=(pid, name, cpu_percent, memory_percent))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            self.log_message(f"成功刷新进程列表，共显示 {len(self.process_tree.get_children())} 个进程")
        except Exception as e:
            self.log_message(f"刷新进程列表时出错: {str(e)}")
            messagebox.showerror("错误", f"刷新进程列表时出错: {str(e)}")
    
    def browse_dll_file(self):
        """浏览并选择DLL文件"""
        file_path = filedialog.askopenfilename(
            title="选择DLL文件",
            filetypes=[("DLL文件", "*.dll"), ("所有文件", "*.*")]
        )
        
        if file_path:
            self.dll_path_var.set(file_path)
            self.log_message(f"已选择DLL文件: {file_path}")
    
    def inject_dll(self):
        """执行DLL注入操作"""
        # 获取选中的进程
        selected_items = self.process_tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个目标进程")
            return
        
        # 获取进程ID
        selected_item = selected_items[0]
        pid = int(self.process_tree.item(selected_item, "values")[0])
        process_name = self.process_tree.item(selected_item, "values")[1]
        
        # 获取DLL文件路径
        dll_path = self.dll_path_var.get()
        if not dll_path or not os.path.exists(dll_path):
            messagebox.showwarning("警告", "请选择有效的DLL文件")
            return
        
        # 获取注入方法
        injection_method = self.injection_method_var.get()
        
        # 确认注入
        confirm = messagebox.askyesno(
            "确认注入",
            f"确定要向进程 '{process_name}' (PID: {pid}) 注入DLL '{dll_path}' 吗？\n注入方法: {injection_method}"
        )
        
        if not confirm:
            return
        
        # 执行注入
        try:
            success = False
            
            self.log_message(f"开始向进程 '{process_name}' (PID: {pid}) 注入DLL")
            self.log_message(f"注入方法: {injection_method}")
            
            if injection_method == "常规注入":
                success = self.injector.inject_dll(pid, dll_path)
            elif injection_method == "反射式注入":
                success = self.injector.reflective_dll_inject(pid, dll_path)
            elif injection_method == "CreateThread注入":
                success = self.injector.create_thread_injection(pid, dll_path)
            elif injection_method == "NtCreateThreadEx注入":
                success = self.injector.nt_create_thread_ex_injection(pid, dll_path)
            
            # 显示结果
            if success:
                messagebox.showinfo("成功", f"DLL注入成功!\n进程: {process_name} (PID: {pid})\nDLL: {dll_path}")
            else:
                messagebox.showerror("失败", "DLL注入失败，请查看日志了解详情")
        except Exception as e:
            self.log_message(f"注入过程中发生错误: {str(e)}")
            messagebox.showerror("错误", f"注入过程中发生错误: {str(e)}")
    
    def log_message(self, message):
        """在日志区域显示消息"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)  # 滚动到最新内容
        self.log_text.config(state=tk.DISABLED)
        
        # 也输出到控制台
        print(message)

def main():
    """主函数，启动GUI应用"""
    try:
        # 检查是否以管理员权限运行
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("警告: 此工具建议以管理员权限运行，否则可能无法注入某些系统进程或其他用户的进程。")
        
        # 创建主窗口
        root = tk.Tk()
        
        # 设置窗口图标（如果有）
        # root.iconbitmap("icon.ico")
        
        # 创建应用实例
        app = DLLInjectorGUI(root)
        
        # 启动主循环
        root.mainloop()
    except Exception as e:
        print(f"应用程序启动失败: {str(e)}")
        input("按Enter键退出...")


if __name__ == '__main__':
    main()