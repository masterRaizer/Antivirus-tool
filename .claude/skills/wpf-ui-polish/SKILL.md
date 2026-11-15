---
name: wpf-ui-polish
description: Правила оформления и надёжности WPF-интерфейса Sentinel.App — тёмная тема с явными контрастными цветами, виртуализация списков, рабочие кнопки, автоподключение к службе. Использовать при любой правке XAML, стилей и ViewModel.
---

# WPF: правила Sentinel.App

1. **Цвета только из словаря `Themes/Dark.xaml`:** `WindowBg #0D1117`, `CardBg #161B22`, `SurfaceElevated #1C2128`, `TextPrimary #F0F6FC`, `TextSecondary #9EA7B3`. Любой `TextBlock`, `TextBox`, `ComboBox`, `ComboBoxItem`, `ToolTip`, `ContextMenu`, `MenuItem` обязан иметь явные `Foreground` и `Background`; стили по умолчанию Windows (чёрный текст на тёмном фоне) недопустимы.
2. **Списки виртуализируются:** в `ListBox`/`ListView`/`DataGrid` задавать `VirtualizingStackPanel.IsVirtualizing="True"` и `VirtualizingStackPanel.VirtualizationMode="Recycling"`; не оборачивать их в `ScrollViewer`, отключающий виртуализацию.
3. **Ни одной нерабочей кнопки:** каждая `Button` привязана к `ICommand`, который действительно вызывает `SentinelRuntime` или IPC-команду службы; результат показывается пользователю (статус, диалог, ошибка).
4. **Два режима:** приложение подключается к `SentinelService` по Named Pipe в фоновом цикле (каждые 2 с); автономный режим включается только пока службы нет, кнопка «Запустить службу» запускает `sc.exe start SentinelService` с повышением прав.
5. **Тексты интерфейса — на русском;** длинные операции — только в фоне, UI-поток не блокируется; коллекции обновляются через `Dispatcher`.
6. После правок XAML — `dotnet build Sentinel.sln` (кросс-сборка проверяет разметку); запуск на Windows не проверялся — записать в `HANDOFF.md`.
