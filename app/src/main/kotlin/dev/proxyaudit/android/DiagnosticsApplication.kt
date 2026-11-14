package dev.proxyaudit.android

import android.app.Application

class DiagnosticsApplication : Application() {
    lateinit var controller: DiagnosticsController
        private set
    val repairSession by lazy { RepairSession(this) }
    val deepDiagnostics by lazy { DeepDiagnosticsSession(this) }
    val proxyCooperation by lazy { ProxyCooperationSession(this) }
    override fun onCreate() { super.onCreate(); controller = DiagnosticsController(this) }
}
