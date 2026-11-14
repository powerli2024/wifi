package dev.proxyaudit.android

import android.app.Application
import android.net.Uri
import android.os.Looper
import dev.proxyaudit.core.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class RepairSessionTest {
    private val context: Application get() = RuntimeEnvironment.getApplication()
    private val original = Uri.parse("content://test/document/original")
    private val target = Uri.parse("content://test/document/copy")
    private val source = "proxies: []\nrules: [MATCH,DIRECT]\ndns:\n  enable: false\n  nameserver: [8.8.8.8]\n"
    private fun await(session: RepairSession) {
        val deadline = System.nanoTime() + 5_000_000_000L
        while (session.busy && System.nanoTime() < deadline) { Thread.sleep(10); shadowOf(Looper.getMainLooper()).idle() }
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse("repair worker did not finish", session.busy)
    }
    private fun imported(value: ByteArray = source.toByteArray()): RepairSession {
        val session = RepairSession(context)
        shadowOf(context.contentResolver).registerInputStream(original, ByteArrayInputStream(value))
        val ticket = session.beginImport()!!
        assertTrue(session.accept(ticket.id, ticket.code, original)); await(session)
        return session
    }
    @Test fun repair_activity_starts_without_reading_or_probing() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        val app = activity.get().application as DiagnosticsApplication
        assertFalse(app.repairSession.hasSource); assertNull(app.repairSession.plan)
        assertFalse(app.controller.busy); assertNull(app.controller.report)
        activity.recreate()
        assertFalse(app.repairSession.hasSource)
        activity.pause().stop().destroy()
    }
    @Test fun import_preview_export_preserve_original_and_write_only_selected_copy() {
        val session = imported()
        assertTrue(session.hasSource); assertNotNull(session.inspection); assertNull(session.plan)
        assertTrue(session.generate()); await(session)
        val expected = session.plan!!.repairedYaml
        val output = ByteArrayOutputStream()
        shadowOf(context.contentResolver).registerOutputStream(target, output)
        shadowOf(context.contentResolver).registerInputStream(target, ByteArrayInputStream(expected.toByteArray()))
        val ticket = session.beginExport()!!
        assertTrue(session.accept(ticket.id, ticket.code, target)); await(session)
        assertEquals(expected, output.toString("UTF-8"))
        assertTrue(expected.contains("rules: [MATCH,DIRECT]"))
        assertEquals(CopyExportState.COPY_READBACK_VERIFIED, session.exportState)
        assertEquals(ticket.id, session.copyEvidence!!.exportId)
        assertEquals(session.copyEvidence!!.expectedSha256, session.copyEvidence!!.readbackSha256)
        assertEquals(expected.toByteArray().size, session.copyEvidence!!.readbackByteCount)
        assertNull(session.copyEvidence!!.issue)
        assertEquals(original, session.sourceDocumentUri)
        assertFalse(session.userReportedApplied)
        assertTrue(session.status.contains("运行效果尚未验证"))
    }
    @Test fun same_document_export_is_rejected_before_opening_output() {
        val session = imported(); session.generate(); await(session)
        val output = ByteArrayOutputStream()
        shadowOf(context.contentResolver).registerOutputStream(original, output)
        val ticket = session.beginExport()!!
        assertTrue(session.accept(ticket.id, ticket.code, original))
        assertEquals(0, output.size()); assertTrue(session.status.contains("拒绝覆盖"))
        assertEquals(CopyExportState.FAILED, session.exportState)
        assertEquals(CopyReadbackIssue.ORIGINAL_PROTECTED, session.copyEvidence!!.issue)
    }
    @Test fun stale_picker_and_restarted_process_cannot_consume_new_config() {
        val session = RepairSession(context)
        val stale = session.beginImport()!!
        session.clear()
        val current = session.beginImport()!!
        assertNotEquals(stale.code, current.code)
        assertFalse(session.accept(stale.id, stale.code, original))
        assertTrue(session.pickerPending)
        val restarted = RepairSession(context)
        restarted.reserveCode(current.code)
        assertFalse(restarted.accept(current.id, current.code, original))
        assertTrue(restarted.beginImport()!!.code > current.code)
        assertFalse(restarted.hasSource)
    }
    @Test fun provider_selection_invalidates_previous_preview_and_pending_picker_freezes_it() {
        val session = imported(); session.generate(); await(session)
        val oldPlan = session.plan!!
        val ticket = session.beginExport()!!
        session.selectProvider(1)
        assertEquals(0, session.providerIndex); assertSame(oldPlan, session.plan)
        session.cancel(ticket.id)
        assertEquals(CopyExportState.CANCELLED_NO_WRITE, session.exportState)
        session.selectProvider(1)
        assertEquals(1, session.providerIndex); assertNull(session.plan)
    }
    @Test fun invalid_utf8_oversize_and_duplicate_keys_are_rejected_without_raw_error_text() {
        for (bytes in listOf(byteArrayOf(0xc3.toByte(), 0x28), ByteArray(RepairSession.MAX_BYTES + 1) { 65 },
            "dns: {nameserver: [credential-secret], nameserver: []}".toByteArray())) {
            val session = imported(bytes)
            assertFalse(session.hasSource); assertNull(session.inspection); assertNull(session.plan)
            assertFalse(session.status.contains("credential-secret"))
        }
    }
    @Test fun clear_drops_content_preview_and_pending_ticket() {
        val session = imported(); session.generate(); await(session)
        val ticket = session.beginExport()!!
        session.clear()
        assertFalse(session.hasSource); assertNull(session.plan); assertNull(session.inspection)
        assertFalse(session.pickerPending)
        assertFalse(session.accept(ticket.id, ticket.code, target))
    }

    private fun ready(): RepairSession = imported().also { assertTrue(it.generate()); await(it) }
    private fun export(session: RepairSession, readback: InputStream, output: OutputStream = ByteArrayOutputStream()) {
        shadowOf(context.contentResolver).registerOutputStream(target, output)
        shadowOf(context.contentResolver).registerInputStream(target, readback)
        val ticket = session.beginExport()!!
        assertTrue(session.accept(ticket.id, ticket.code, target))
    }
    private fun verified(): RepairSession = ready().also {
        export(it, ByteArrayInputStream(it.plan!!.repairedYaml.toByteArray()))
        await(it)
        assertEquals(CopyExportState.COPY_READBACK_VERIFIED, it.exportState)
    }
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    @Test fun readback_happens_after_output_close_and_preserves_original_digest() {
        val session = ready()
        val originalOutput = ByteArrayOutputStream()
        shadowOf(context.contentResolver).registerOutputStream(original, originalOutput)
        var outputClosed = false
        val output = object : ByteArrayOutputStream() {
            override fun close() { outputClosed = true; super.close() }
        }
        val readback = object : InputStream() {
            private var input: InputStream? = null
            override fun read(): Int {
                check(outputClosed) { "readback before close" }
                val value = input ?: ByteArrayInputStream(output.toByteArray()).also { input = it }
                return value.read()
            }
        }
        export(session, readback, output); await(session)
        assertEquals(CopyExportState.COPY_READBACK_VERIFIED, session.exportState)
        assertEquals(digest(source.toByteArray()), session.copyEvidence!!.sourceSha256)
        assertEquals(digest(output.toByteArray()), session.copyEvidence!!.readbackSha256)
        assertEquals(0, originalOutput.size())
    }

    @Test fun absent_read_permission_or_provider_error_never_claims_verified_or_applied() {
        for (failure in listOf(SecurityException("credential-secret"), IOException("credential-secret"))) {
            val session = ready()
            val output = ByteArrayOutputStream()
            export(session, object : InputStream() { override fun read(): Int = throw failure }, output)
            await(session)
            assertEquals(session.plan!!.repairedYaml, output.toString("UTF-8"))
            assertEquals(CopyExportState.COPY_WRITTEN_UNVERIFIED, session.exportState)
            assertEquals(CopyReadbackIssue.READ_UNAVAILABLE, session.copyEvidence!!.issue)
            assertFalse(session.canMarkUserReportedApplied)
            assertFalse(session.markUserReportedApplied())
            assertFalse(session.status.contains("credential-secret"))
            assertTrue(session.status.contains("内容未核实"))
        }
    }

    @Test fun truncated_or_replaced_readback_fails_even_if_it_is_valid_yaml() {
        for (replacement in listOf(ByteArray(0), source.toByteArray(), "proxies: []\n".toByteArray())) {
            val session = ready()
            export(session, ByteArrayInputStream(replacement)); await(session)
            assertEquals(CopyExportState.FAILED, session.exportState)
            assertEquals(CopyReadbackIssue.CONTENT_MISMATCH, session.copyEvidence!!.issue)
            assertEquals(replacement.size, session.copyEvidence!!.readbackByteCount)
            assertEquals(digest(replacement), session.copyEvidence!!.readbackSha256)
            assertFalse(session.markUserReportedApplied())
            assertTrue(session.status.contains("请勿导入"))
        }
    }

    @Test fun readback_size_limit_consumes_only_one_extra_byte_and_closes_stream() {
        val session = ready()
        var bytesRead = 0
        var closed = false
        val input = object : InputStream() {
            override fun read(): Int { bytesRead++; return 65 }
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                buffer.fill(65, offset, offset + length); bytesRead += length; return length
            }
            override fun close() { closed = true }
        }
        export(session, input); await(session)
        assertEquals(CopyExportState.FAILED, session.exportState)
        assertEquals(CopyReadbackIssue.TOO_LARGE, session.copyEvidence!!.issue)
        assertEquals(RepairSession.MAX_BYTES + 1, bytesRead)
        assertTrue(closed)
    }

    @Test fun write_or_close_failure_is_failed_copy_without_exposing_exception_text() {
        for (failOnClose in listOf(false, true)) {
            val session = ready()
            var inputTouched = false
            var closed = false
            val output = object : OutputStream() {
                override fun write(value: Int) { if (!failOnClose) throw IOException("credential-secret") }
                override fun close() { closed = true; if (failOnClose) throw IOException("credential-secret") }
            }
            export(session, object : InputStream() { override fun read(): Int { inputTouched = true; return -1 } }, output)
            await(session)
            assertEquals(CopyExportState.FAILED, session.exportState)
            assertEquals(CopyReadbackIssue.WRITE_FAILED, session.copyEvidence!!.issue)
            assertFalse(inputTouched); assertTrue(closed)
            assertFalse(session.status.contains("credential-secret"))
            assertFalse(session.markUserReportedApplied())
        }
    }

    @Test fun same_provider_document_id_alias_is_rejected_and_never_opened_for_write() {
        val session = ready()
        val alias = Uri.parse("content://test/tree/another/document/original")
        val output = ByteArrayOutputStream()
        shadowOf(context.contentResolver).registerOutputStream(alias, output)
        val ticket = session.beginExport()!!
        assertTrue(session.accept(ticket.id, ticket.code, alias))
        assertFalse(session.busy); assertEquals(0, output.size())
        assertEquals(CopyReadbackIssue.ORIGINAL_PROTECTED, session.copyEvidence!!.issue)
    }

    @Test fun user_import_confirmation_and_baseline_are_process_only_and_invalidated_by_plan_change() {
        val baseline = "f61f6488-57ad-4ed1-a5d5-4f86e567ae19"
        val session = verified()
        assertTrue(session.associateBaseline(baseline))
        assertTrue(session.canMarkUserReportedApplied)
        assertTrue(session.markUserReportedApplied()); assertFalse(session.markUserReportedApplied())
        assertTrue(session.userReportedApplied)
        assertTrue(session.status.contains("生效状态未独立核验"))
        assertEquals(baseline, session.baselineRunId)
        val restarted = RepairSession(context)
        assertEquals(CopyExportState.NONE, restarted.exportState)
        assertNull(restarted.copyEvidence); assertNull(restarted.baselineRunId)
        assertFalse(restarted.userReportedApplied)
        session.selectProvider(1)
        assertNull(session.plan); assertNull(session.copyEvidence); assertNull(session.baselineRunId)
        assertEquals(CopyExportState.NONE, session.exportState)
        assertFalse(session.userReportedApplied); assertFalse(session.markUserReportedApplied())
    }

    @Test fun regeneration_new_source_and_clear_drop_old_copy_confirmation() {
        for (action in 0..2) {
            val session = verified()
            assertTrue(session.associateBaseline("f61f6488-57ad-4ed1-a5d5-4f86e567ae19"))
            assertTrue(session.markUserReportedApplied())
            when (action) {
                0 -> { assertTrue(session.generate()); await(session) }
                1 -> {
                    shadowOf(context.contentResolver).registerInputStream(original, ByteArrayInputStream(source.toByteArray()))
                    val ticket = session.beginImport()!!
                    assertTrue(session.accept(ticket.id, ticket.code, original)); await(session)
                }
                else -> session.clear()
            }
            assertNull(session.copyEvidence); assertNull(session.baselineRunId)
            assertFalse(session.userReportedApplied); assertFalse(session.canMarkUserReportedApplied)
        }
    }

    @Test fun generating_preview_explicitly_freezes_selected_baseline_identity() {
        val baseline = "f61f6488-57ad-4ed1-a5d5-4f86e567ae19"
        val session = imported()
        assertTrue(session.generate(baseline)); await(session)
        assertEquals(baseline, session.baselineRunId)
        val plan = session.plan
        assertFalse(session.generate("credential-secret"))
        assertSame(plan, session.plan); assertEquals(baseline, session.baselineRunId)
        assertFalse(session.status.contains("credential-secret"))
        val ticket = session.beginExport()!!
        assertFalse(session.associateBaseline(null))
        assertEquals(baseline, session.baselineRunId)
        session.cancel(ticket.id)
        session.selectProvider(1)
        assertNull(session.baselineRunId)
    }

    @Test fun cancelled_picker_cannot_write_and_new_export_does_not_reuse_old_confirmation() {
        val session = verified()
        assertTrue(session.markUserReportedApplied())
        val ticket = session.beginExport()!!
        assertFalse(session.userReportedApplied); assertNull(session.copyEvidence)
        session.cancel(ticket.id)
        assertEquals(CopyExportState.CANCELLED_NO_WRITE, session.exportState)
        assertFalse(session.accept(ticket.id, ticket.code, target))
        assertFalse(session.busy); assertFalse(session.cancelActive())
    }

    @Test fun cancel_during_provider_write_keeps_slot_until_return_and_never_claims_no_write() {
        val session = ready()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var closed = false
        val output = object : OutputStream() {
            override fun write(value: Int) {
                entered.countDown()
                check(release.await(3, TimeUnit.SECONDS))
                throw IOException("credential-secret")
            }
            override fun close() { closed = true }
        }
        export(session, ByteArrayInputStream(ByteArray(0)), output)
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            assertTrue(session.cancelActive()); assertFalse(session.cancelActive())
            assertTrue(session.busy); assertNull(session.beginExport()); assertNull(session.beginImport())
            assertFalse(session.generate()); session.clear(); assertTrue(session.hasSource)
        } finally { release.countDown() }
        await(session)
        assertTrue(closed)
        assertEquals(CopyExportState.CANCELLED_WRITE_UNKNOWN, session.exportState)
        assertEquals(CopyReadbackIssue.CANCELLED, session.copyEvidence!!.issue)
        assertFalse(session.status.contains("credential-secret"))
        assertFalse(session.markUserReportedApplied())
        assertNotNull(session.beginExport())
    }

    @Test fun cancel_during_readback_freezes_unverified_result_and_allows_no_stale_completion() {
        val session = ready()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var closed = false
        val validBytes = session.plan!!.repairedYaml.toByteArray()
        val input = object : ByteArrayInputStream(validBytes) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                entered.countDown()
                check(release.await(3, TimeUnit.SECONDS))
                return super.read(buffer, offset, length)
            }
            override fun close() { closed = true; super.close() }
        }
        export(session, input)
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            assertEquals(CopyExportState.VERIFYING, session.exportState)
            assertTrue(session.cancelActive()); assertTrue(session.busy)
            assertFalse(session.markUserReportedApplied()); assertNull(session.beginImport())
        } finally { release.countDown() }
        await(session)
        assertTrue(closed)
        assertEquals(CopyExportState.COPY_WRITTEN_UNVERIFIED, session.exportState)
        assertEquals(CopyReadbackIssue.CANCELLED, session.copyEvidence!!.issue)
        assertNull(session.copyEvidence!!.readbackSha256)
        session.clear()
        assertEquals(CopyExportState.NONE, session.exportState); assertNull(session.copyEvidence)
    }
}
