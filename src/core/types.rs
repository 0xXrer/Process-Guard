#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub create_time: u64,
    pub image_base: u64,
    pub entry_point: u64,
}

#[derive(Debug)]
pub enum InjectionType {
    ProcessHollowing,
    SetWindowsHookEx,
    ApcQueue,
    ThreadHijacking,
    ReflectiveDll,
    ManualMapping,
    AtomBombing,
    ShimInjection,
    ProcessDoppelganging,
    DirectSyscalls,
    HeavensGate,
}
