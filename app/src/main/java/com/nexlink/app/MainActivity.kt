
package com.nexlink.app

import android.app.Activity
import android.os.Bundle
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.CheckBox
import android.app.AppOpsManager
import android.app.usage.UsageStats
import android.app.usage.UsageStatsManager
import android.os.Process
import com.nexlink.app.data.local.NexlinkDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job

class MainActivity : Activity() {

    private val backgroundColor = Color.rgb(13, 18, 30)
    private val cardColor = Color.rgb(25, 33, 49)
    private val accentColor = Color.rgb(75, 145, 255)
    private val textColor = Color.WHITE
    private val secondaryColor = Color.rgb(165, 177, 198)
    private var notificationHistoryJob: Job? = null
   
    private val preferences by lazy {
        getSharedPreferences("nexlink_settings", Context.MODE_PRIVATE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DeviceIdentity.getOrCreateDeviceId(this)
        window.statusBarColor = backgroundColor
        window.navigationBarColor = backgroundColor

        val savedRole = preferences.getString("device_role", null)

        if (savedRole == null) {
            showRoleSelection()
        } else {
            showDashboard(savedRole)
        }
    }
    private fun hasUsageAccess(): Boolean {
       val appOps = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager

       val mode = appOps.checkOpNoThrow(
        AppOpsManager.OPSTR_GET_USAGE_STATS,
        Process.myUid(),
        packageName
    )

    return mode == AppOpsManager.MODE_ALLOWED
    }
    private fun showRoleSelection() {
        val root = createRoot()

        root.addView(
            makeText("NEXLINK", 32f, textColor, true),
            params(bottom = 8)
        )

        root.addView(
            makeText("الإعداد الأولي", 22f, textColor, true),
            params(top = 24, bottom = 10)
        )

        root.addView(
            makeText(
                "اختر دور هذا الهاتف في شبكة NEXLINK",
                15f,
                secondaryColor
            ),
            params(bottom = 28)
        )

        root.addView(
            makeRoleCard(
                "SUPER ADMIN",
                "الجهاز الرئيسي",
                "إدارة الأجهزة المرتبطة ومتابعة حالة الاتصال وإرسال طلبات المشاركة."
            ) {
                saveRole("admin")
            },
            params(bottom = 16)
        )

        root.addView(
            makeRoleCard(
                "BASIC DEVICE",
                "الجهاز التابع",
                "استقبال طلبات الربط ومراجعة الصلاحيات ومنح التفويض أو إلغائه."
            ) {
                saveRole("basic")
            },
            params(bottom = 24)
        )

        root.addView(
            makeText(
                "يمكن إدارة التفويضات لاحقاً من إعدادات التطبيق. " +
                    "اختيار الدور لا يمنح أي صلاحيات تلقائياً.",
                12f,
                secondaryColor
            ),
            params(top = 8)
        )

        setContentView(makeScroll(root))
    }

    private fun saveRole(role: String) {
        preferences.edit()
            .putString("device_role", role)
            .apply()

        showDashboard(role)
    }

    private fun showDashboard(role: String) {
        val isAdmin = role == "admin"
        val root = createRoot()

        root.addView(
            makeText("NEXLINK", 30f, textColor, true),
            params()
        )

        root.addView(
            makeText(
                if (isAdmin) "الجهاز الرئيسي • SUPER ADMIN"
                else "الجهاز التابع • BASIC DEVICE",
                14f,
                accentColor,
                true
            ),
            params(bottom = 24)
        )

        val deviceCard = makeCard()

        deviceCard.addView(
            makeText("حالة الاتصال", 18f, textColor, true),
            params(bottom = 12)
        )

        deviceCard.addView(
            makeText(
                "●  لا يوجد جهاز متصل حالياً",
                15f,
                Color.rgb(255, 190, 80)
            ),
            params(bottom = 8)
        )

        deviceCard.addView(
            makeText(
                "قم بربط جهاز آخر للبدء",
                13f,
                secondaryColor
            ),
            params()
        )

        root.addView(deviceCard, params(bottom = 20))

        root.addView(
            makeText("خدمة الاتصال", 20f, textColor, true),
            params(bottom = 12)
        )

        val serviceCard = makeCard()

        serviceCard.addView(
            makeText(
                "إدارة تشغيل خدمة NEXLINK على هذا الهاتف",
                13f,
                secondaryColor
            ),
            params(bottom = 16)
        )

        serviceCard.addView(
            makeServiceButton("تشغيل خدمة الاتصال") {
                startConnectionService()
            },
            params(bottom = 10)
        )

        serviceCard.addView(
            makeServiceButton("إيقاف خدمة الاتصال") {
                stopConnectionService()
            },
            params()
        )

        serviceCard.addView(
            makeServiceButton("إعداد صلاحية الإشعارات") {
                startActivity(
                    Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
                )
            },
            params(top = 10)
        )

        serviceCard.addView(
            makeServiceButton("إعداد صلاحية نشاط التطبيقات") {
                startActivity(
                    Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                )
            },
            params(top = 10)
        )

        root.addView(serviceCard, params(bottom = 20))

        root.addView(
            makeText("إدارة الأجهزة", 20f, textColor, true),
            params(bottom = 12)
        )
        
        if (isAdmin) {
            root.addView(
                makeActionCard(
                    "＋",
                    "ربط جهاز جديد",
                    "إنشاء اتصال آمن مع جهاز آخر"
                ),
                params(bottom = 10)
            )
        }

        root.addView(
            makeActionCard(
                "▣",
                "مشاركة الشاشة",
                "عرض الشاشة بعد موافقة الجهاز الآخر"
            ),
            params(bottom = 10)
        )

        root.addView(
            makeActionCard(
                "◉",
                "الإشعارات",
                "إدارة مشاركة إشعارات الجهاز"
            ) {
                showNotificationAppSelection()
            },
            params(bottom = 10)
        )

        root.addView(
            makeActionCard(
                "▤",
                "نشاط التطبيقات",
                "عرض التطبيقات ومدة الاستخدام"
            ),
            params(bottom = 10)
        )

        root.addView(
            makeActionCard(
                "▧",
                "الملفات والوسائط",
                "مشاركة الصور والفيديو والملفات"
            ),
            params(bottom = 10)
        )

        root.addView(
            makeText("الخصوصية والأمان", 20f, textColor, true),
            params(top = 18, bottom = 12)
        )

        root.addView(
            makeActionCard(
                "⚙",
                "الصلاحيات والتفويض",
                "مراجعة الأذونات وإلغاء التفويض"
            ),
            params(bottom = 10)
        )

        root.addView(
            makeText(
                "NEXLINK • الإصدار 1.0",
                12f,
                secondaryColor
            ).apply {
                gravity = Gravity.CENTER
            },
            params(top = 24, bottom = 12)
        )

        setContentView(makeScroll(root))
    }

    private fun showNotificationAppSelection() {
        val role = preferences.getString("device_role", "basic") ?: "basic"
        val root = createRoot()

        root.addView(
            makeText("مشاركة الإشعارات", 26f, textColor, true),
            params(bottom = 10)
        )

        root.addView(
            makeText(
                "اختر التطبيقات التي تسمح بمشاركة إشعاراتها مع الجهاز المرتبط.",
                14f,
                secondaryColor
            ),
            params(bottom = 20)
        )

        root.addView(
            makeServiceButton("العودة إلى لوحة التحكم") {
                showDashboard(role)
            },
            params(bottom = 12)
        )

        val eventCountView = makeText(
            "الأحداث المحفوظة محلياً: جارٍ التحميل...",
            14f,
            secondaryColor
        )


        root.addView(
           eventCountView, 
            params(bottom = 12)
        )

        root.addView(
           makeServiceButton("عرض سجل الإشعارات المحفوظة") {
        showNotificationHistory() 
            },
            params(bottom = 20)
        )
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val count = NexlinkDatabase
                    .getInstance(this@MainActivity)
                    .syncEventDao()
                    .getEventCount()

                runOnUiThread {
                    eventCountView.text =
                        "الأحداث المحفوظة محلياً: $count"
                }
            } catch (error: Exception) {
                runOnUiThread {
                    eventCountView.text = "تعذّرت قراءة عدد الأحداث"
                }
            }
        }

        val selectedApps = preferences.getStringSet(
            "selected_notification_apps",
            emptySet()
        )?.toMutableSet() ?: mutableSetOf()

        val launchIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }

        val apps = packageManager.queryIntentActivities(
            launchIntent,
            0
        ).distinctBy {
            it.activityInfo.packageName
        }.filter {
            it.activityInfo.packageName != packageName
        }.sortedBy {
            it.loadLabel(packageManager).toString().lowercase()
        }

        if (apps.isEmpty()) {
            root.addView(
                makeText(
                    "لم يتم العثور على تطبيقات.",
                    14f,
                    secondaryColor
                ),
                params()
            )
        }

        for (app in apps) {
            val appPackage = app.activityInfo.packageName
            val appName = app.loadLabel(packageManager).toString()

            val appCard = makeCard()

            val checkBox = CheckBox(this).apply {
                text = appName
                textSize = 16f
                setTextColor(textColor)
                isChecked = appPackage in selectedApps

                setOnCheckedChangeListener { _, checked ->
                    if (checked) {
                        selectedApps.add(appPackage)
                    } else {
                        selectedApps.remove(appPackage)
                    }

                    preferences.edit()
                        .putStringSet(
                            "selected_notification_apps",
                            selectedApps.toSet()
                        )
                        .apply()
                }
            }

            appCard.addView(checkBox)
            root.addView(appCard, params(bottom = 8))
        }

        root.addView(
            makeText(
                "يمكنك تغيير اختياراتك في أي وقت. " +
                    "اختيار التطبيق يسمح بإدراج إشعاراته ضمن المشاركة، " +
                    "ولا يعني إرسالها تلقائياً إلى جهاز آخر.",
                12f,
                secondaryColor
            ),
            params(top = 16, bottom = 20)
        )

        setContentView(makeScroll(root))
    }
 
    private fun showNotificationHistory() {
    val root = createRoot()

    root.addView(
        makeText("سجل الإشعارات المحفوظة", 24f, textColor, true),
        params(bottom = 12)
    )

    root.addView(
        makeServiceButton("العودة إلى إعدادات الإشعارات") {
            notificationHistoryJob?.cancel()
            showNotificationAppSelection()
        },
        params(bottom = 16)
    )

    val historyContainer = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
    }

    root.addView(
        historyContainer,
        params(bottom = 16)
    )

    setContentView(makeScroll(root))

    notificationHistoryJob?.cancel()

    notificationHistoryJob = CoroutineScope(Dispatchers.IO).launch {
        val dao = NexlinkDatabase
            .getInstance(this@MainActivity)
            .syncEventDao()

        dao.observeNotifications().collect { events ->
            runOnUiThread {
                historyContainer.removeAllViews()

                if (events.isEmpty()) {
                    historyContainer.addView(
                        makeText(
                            "لا توجد إشعارات محفوظة حتى الآن.",
                            14f,
                            secondaryColor
                        ),
                        params(bottom = 12)
                    )
                }

                for (event in events) {
                    val card = makeCard()

                    card.addView(
                        makeText(
                            "الحدث: ${event.type}",
                            15f,
                            textColor,
                            true
                        ),
                        params(bottom = 8)
                    )

                    card.addView(
                        makeText(
                            event.payload,
                            13f,
                            secondaryColor
                        ),
                        params(bottom = 8)
                    )

                    card.addView(
                        makeText(
                            "وقت الحفظ: ${java.text.DateFormat.getDateTimeInstance().format(event.createdAt)}",
                            12f,
                            secondaryColor
                        ),
                        params(bottom = 8)
                    )

                    historyContainer.addView(
                        card,
                        params(bottom = 10)
                    )
                }
            }
        }
    }
}

    private fun startConnectionService() {
        val intent = Intent(this, ConnectionService::class.java).apply {
            action = ConnectionService.ACTION_START
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopConnectionService() {
        stopService(Intent(this, ConnectionService::class.java))
    }

    private fun makeServiceButton(
        label: String,
        action: () -> Unit
    ): TextView {
        return makeText(label, 15f, textColor, true).apply {
            gravity = Gravity.CENTER
            setPadding(12, 16, 12, 16)
            setBackgroundColor(accentColor)
            isClickable = true
            isFocusable = true
            setOnClickListener { action() }
        }
    }

    private fun createRoot(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(backgroundColor)
            setPadding(20, 28, 20, 20)
        }
    }

    private fun makeScroll(content: View): ScrollView {
        return ScrollView(this).apply {
            isFillViewport = true
            addView(content)
        }
    }

    private fun makeRoleCard(
        code: String,
        title: String,
        description: String,
        action: () -> Unit
    ): LinearLayout {
        val card = makeCard()

        card.addView(
            makeText(code, 14f, accentColor, true),
            params(bottom = 10)
        )

        card.addView(
            makeText(title, 20f, textColor, true),
            params(bottom = 8)
        )

        card.addView(
            makeText(description, 14f, secondaryColor),
            params(bottom = 18)
        )

        val button = makeText(
            "اختيار هذا الدور",
            15f,
            textColor,
            true
        ).apply {
            gravity = Gravity.CENTER
            setPadding(12, 16, 12, 16)
            setBackgroundColor(accentColor)
            isClickable = true
            isFocusable = true
            setOnClickListener { action() }
        }

        card.addView(button, params())

        return card
    }

    private fun makeText(
        value: String,
        size: Float,
        color: Int,
        bold: Boolean = false
    ): TextView {
        return TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)

            if (bold) {
                setTypeface(null, Typeface.BOLD)
            }

            gravity = Gravity.RIGHT
        }
    }

    private fun makeCard(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(18, 18, 18, 18)
            setBackgroundColor(cardColor)
        }
    }

    private fun makeActionCard(
        symbol: String,
        title: String,
        description: String,
        action: (() -> Unit)? = null
    ): LinearLayout {
        val card = makeCard()
        card.orientation = LinearLayout.HORIZONTAL
        card.gravity = Gravity.CENTER_VERTICAL

        val icon = makeText(
            symbol,
            25f,
            accentColor,
            true
        ).apply {
            gravity = Gravity.CENTER
            width = 48
        }

        val details = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        details.addView(
            makeText(title, 16f, textColor, true)
        )

        details.addView(
            makeText(description, 12f, secondaryColor)
        )

        card.addView(icon)
        card.addView(details)

        if (action != null) {
            card.isClickable = true
            card.isFocusable = true
            card.setOnClickListener { action() }
        }

        return card
    }

    private fun params(
        top: Int = 0,
        bottom: Int = 0
    ): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = top
            bottomMargin = bottom
        }
    }

    private fun readAppUsage(): List<UsageStats> {
        val usageManager =
            getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager

        val endTime = System.currentTimeMillis()
        val startTime = endTime - 24L * 60L * 60L * 1000L

        return usageManager.queryUsageStats(
            UsageStatsManager.INTERVAL_DAILY,
            startTime,
            endTime
        ).filter {
            it.totalTimeInForeground > 0 &&
                it.packageName != packageName
        }
    }

    override fun onResume() {
        super.onResume()
        val granted = hasUsageAccess()
        android.util.Log.i(
            "NEXLINK_USAGE",
            "Usage access granted: $granted"
        )

        if (granted) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val usageList = readAppUsage()
                    android.util.Log.i(
                        "NEXLINK_USAGE",
                        "Apps found: ${usageList.size}"
                    )

                    usageList.forEach { usage ->
                        android.util.Log.i(
                            "NEXLINK_USAGE",
                            "Package: ${usage.packageName}, " +
                                "Foreground time: ${usage.totalTimeInForeground} ms"
                        )
                    }
                } catch (error: Exception) {
                    android.util.Log.e(
                        "NEXLINK_USAGE",
                        "Failed to read app usage",
                        error
                    )
                }
            }
        }
    }

}

