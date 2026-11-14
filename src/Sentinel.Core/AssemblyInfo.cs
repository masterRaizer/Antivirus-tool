using System.Runtime.InteropServices;

// Нативные библиотеки (wintrust.dll и др.) загружаются только из System32 — защита от DLL hijacking.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
