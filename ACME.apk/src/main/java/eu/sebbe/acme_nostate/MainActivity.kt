package eu.sebbe.acme_nostate

import android.content.res.Configuration
import android.os.Bundle
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.Icon
import androidx.compose.material3.TextField
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.annotation.Keep
import java.io.PrintWriter
import java.io.StringWriter
import java.util.Base64
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECFieldFp
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.Signature
import kotlinx.serialization.Serializable
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import okhttp3.MediaType.Companion.toMediaType
import retrofit2.Retrofit
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Body
import retrofit2.http.Url
import retrofit2.Response
import retrofit2.http.Headers
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner

val IconVisibility: ImageVector by lazy {
    ImageVector.Builder(
        name = "Visibility",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f
    ).path(fill = SolidColor(Color.Black), pathFillType = PathFillType.EvenOdd) {
            moveTo(12f, 4.5f)
            curveTo(7f, 4.5f, 2.73f, 7.61f, 1f, 12f)
            curveToRelative(1.73f, 4.39f, 6f, 7.5f, 11f, 7.5f)
            reflectiveCurveToRelative(9.27f, -3.11f, 11f, -7.5f)
            curveToRelative(-1.73f, -4.39f, -6f, -7.5f, -11f, -7.5f)
            close()
            moveTo(12f, 7f)
            arcTo(5f, 5f, 0f, isMoreThanHalf = true, isPositiveArc = true, 12f, 17f)
            arcTo(5f, 5f, 0f, isMoreThanHalf = true, isPositiveArc = true, 12f, 7f)
            close()
            moveTo(12f, 9.5f)
            arcTo(2.5f, 2.5f, 0f, isMoreThanHalf = true, isPositiveArc = true, 12f, 14.5f)
            arcTo(2.5f, 2.5f, 0f, isMoreThanHalf = true, isPositiveArc = true, 12f, 9.5f)
            close()
        }.build()
    }

@Keep
@Serializable
data class Directory(
    @SerialName("newNonce") val newNonce: String,
    @SerialName("newAccount") val newAccount: String,
    @SerialName("newOrder") val newOrder: String,
    @SerialName("meta") val meta: Meta
)

@Keep
@Serializable
data class Meta(
    @SerialName("caaIdentities") val caaIdentities: List<String>
)

@Keep
@Serializable
data class Order(
    @SerialName("status") val status: String,
    @SerialName("authorizations") val authorizations: List<String>,
    @SerialName("finalize") val finalize: String,
    @SerialName("certificate") val certificate: String? = ""
)

@Keep
@Serializable
data class Autz(
    @SerialName("challenges") val challenges: List<Chal>
)

@Keep
@Serializable
data class Chal(
    @SerialName("url") val url: String,
    @SerialName("type") val type: String
)

@Keep
interface AcmeApi {
    @GET("directory")
    suspend fun getDirectory(): Directory

    @Headers("Content-Type: application/jose+json")
    @POST
    suspend fun getOrder(@Url url: String, @Body body: RequestBody): Response<Order>

    @Headers("Content-Type: application/jose+json")
    @POST
    suspend fun getAutz(@Url url: String, @Body body: RequestBody): Response<Autz>

    @GET
    suspend fun blankGet(@Url url: String): Response<Void>

    @Headers("Content-Type: application/jose+json")
    @POST
    suspend fun blankPost(@Url url: String, @Body body: RequestBody): Response<Void>

    @Headers("Content-Type: application/jose+json")
    @POST
    suspend fun fetchcertificate(@Url url: String, @Body body: RequestBody): Response<ResponseBody>
}



private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFFD0BCFF),
    secondary = Color(0xFFCCC2DC),
    tertiary = Color(0xFFEFB8C8)
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF6650a4),
    secondary = Color(0xFF625b71),
    tertiary = Color(0xFF7D5260)
)

private var staging = 1
private var nonce: String = ""

@Composable
fun AcmenostateTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val typography = Typography(
        bodyLarge = TextStyle(
            fontFamily = FontFamily.Default,
            fontWeight = FontWeight.Normal,
            fontSize = 16.sp,
            lineHeight = 24.sp,
            letterSpacing = 0.5.sp
        ) )
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = typography,
        content = content
    )
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AcmenostateTheme {
                AcmeForm(modifier = Modifier.padding(6.dp))
            }
        }
    }
}

@Composable
fun AcmeForm(modifier: Modifier = Modifier) {
    var progress by remember { mutableIntStateOf(0) }
    val isRunning = progress > 0
    val bgjob = rememberCoroutineScope()
    val keyboardController = LocalSoftwareKeyboardController.current
    val domains = rememberTextFieldState()
    var format by remember { mutableStateOf("PEM") }
    val passwordState = rememberTextFieldState()
    val domainState = rememberTextFieldState()
    val certState = rememberTextFieldState()
    var showPassword by remember { mutableStateOf(false) }
    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
    val clipboardManager = LocalClipboard.current
    var copied = 1


if (isLandscape) {
    Row(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.weight(1f).padding(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(" \nCertificate generation details:", style = MaterialTheme.typography.labelLarge)
            SecureTextField(
                enabled = !isRunning,
                state = passwordState,
                label = { Text("Password") },
                textObfuscationMode = if (showPassword) {
                    TextObfuscationMode.Visible
                } else {
                    TextObfuscationMode.RevealLastTyped
                },
                modifier = Modifier.fillMaxWidth()
                    .onFocusChanged { focusState ->
                        if (focusState.isFocused) {
                                copied = 1
                            }
                    },
                trailingIcon = {
                    IconButton(enabled = !isRunning, onClick = { showPassword = !showPassword; copied = 1 }) {
                        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(24.dp)) {
                            Icon(
                                imageVector = IconVisibility,
                                contentDescription = if (showPassword) "Hide password" else "Show password"
                            )
                            if (!showPassword) {
                                Canvas(modifier = Modifier.matchParentSize()) {
                                    drawLine(
                                        color = Color.Red,
                                        start = Offset(x = size.width * 0.2f, y = size.height * 0.2f),
                                        end = Offset(x = size.width * 0.8f, y = size.height * 0.8f),
                                        strokeWidth = 2.dp.toPx(),
                                        cap = StrokeCap.Round
                                    )
                                }
                            }
                        }
                    }
                }
            )
            TextField(
                enabled = !isRunning,
                state = domains,
                label = { Text("Domains") },
                modifier = Modifier.fillMaxWidth()
                    .onFocusChanged { focusState ->
                        if (focusState.isFocused) {
                                copied = 1
                            }
                    }
            )

            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(
                    enabled = !isRunning,
                    selected = (format == "PEM"),
                    onClick = { format = "PEM"; copied = 1; keyboardController?.hide()})
                Text("PEM-format", modifier = Modifier.padding(end = 6.dp))

                RadioButton(
                    enabled = !isRunning,
                    selected = (format == "JWK"),
                    onClick = { format = "JWK"; copied = 1; keyboardController?.hide()})
                Text("JWK-format")
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Button(enabled = !isRunning, onClick = {
                    keyboardController?.hide()
                    copied = 1
                    bgjob.launch {
                        val (fullcert, fulldomain) = genCertificate(
                            passwordState.text.toString(),
                            domains.text.toString(), onProgress = { currentProgress -> progress = currentProgress} )
                        certState.edit { replace(0, length, fullcert) }
                        domainState.edit { replace(0, length, fulldomain) }

                    }
                }, modifier = Modifier.weight(1f)) {
                    Text(
                        if (progress == 0) {
                            "Generate DNS\n and Certificate"
                        } else {
                            "Generating...\n[" + "#".repeat(progress) + "_".repeat(9 - progress) + "]"
                        }, textAlign = TextAlign.Center
                    )
                }

                Button(enabled = !isRunning, onClick = {
                    keyboardController?.hide()
                    copied = 1
                    val (fullcert, fulldomain) = genKey(
                        passwordState.text.toString(),
                        domains.text.toString(), format
                    )
                    certState.edit { replace(0, length, fullcert) }
                    domainState.edit { replace(0, length, fulldomain) }
                }, modifier = Modifier.weight(1f)) {
                    Text(
                        "Generate TLSA\nKey and CSR",
                        textAlign = TextAlign.Center
                    )
                }
            }

            Text(
                "\nTo only generate DNS Record without Certificate, or generate TLSA and Key without CSR, leave \"Domains\" field blank.\nDNS-record to add:",
                style = MaterialTheme.typography.labelLarge
            )
            SelectionContainer {
                TextField(
                    state = domainState,
                    readOnly = true,
                    modifier = Modifier.fillMaxWidth()
                        .onFocusChanged { focusState ->
                            if (focusState.isFocused) {
                                    keyboardController?.hide()
                                    if (copied != 2) {
                                        val clipData = android.content.ClipData.newPlainText("record", certState.text.toString())
                                        val clipEntry = ClipEntry(clipData)
                                        bgjob.launch {
                                            clipboardManager.setClipEntry(clipEntry)
                                        }
                                       copied = 2
                                    }
                                }
                        },
                )
            }

        }
        Column(modifier = Modifier.weight(1f).padding(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(" \nCertificate or private key:", style = MaterialTheme.typography.labelLarge)
            SelectionContainer {
                TextField(
                    textStyle = TextStyle(fontFamily = FontFamily.Monospace),
                    state = certState,
                    readOnly = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .fillMaxHeight()
                        .onFocusChanged { focusState ->
                            if (focusState.isFocused) {
                                    keyboardController?.hide()
                                    if (copied != 3) {
                                        val clipData = android.content.ClipData.newPlainText("certificate", certState.text.toString())
                                        val clipEntry = ClipEntry(clipData)
                                        bgjob.launch {
                                            clipboardManager.setClipEntry(clipEntry)
                                        }
                                        copied = 3
                                    }
                                }
                        }
                )
            }
        }
        }
}
    else {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(" \nCertificate generation details:", style = MaterialTheme.typography.labelLarge)
        SecureTextField(
            enabled = !isRunning,
            state = passwordState,
            label = { Text("Password") },
            textObfuscationMode = if (showPassword) {
                TextObfuscationMode.Visible
            } else {
                TextObfuscationMode.RevealLastTyped
            },
            modifier = Modifier.fillMaxWidth()
                .onFocusChanged { focusState ->
                    if (focusState.isFocused) {
                            copied = 1
                        }
                },
            trailingIcon = {
                IconButton(enabled = !isRunning, onClick = { showPassword = !showPassword; copied = 1 }) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(24.dp)) {
                        Icon(
                            imageVector = IconVisibility,
                            contentDescription = if (showPassword) "Hide password" else "Show password"
                        )
                        if (!showPassword) {
                            Canvas(modifier = Modifier.matchParentSize()) {
                                drawLine(
                                    color = Color.Red,
                                    start = Offset(x = size.width * 0.2f, y = size.height * 0.2f),
                                    end = Offset(x = size.width * 0.8f, y = size.height * 0.8f),
                                    strokeWidth = 2.dp.toPx(),
                                    cap = StrokeCap.Round
                                )
                            }
                        }
                    }
                }
            }
        )
        TextField(
            enabled = !isRunning,
            state = domains,
            label = { Text("Domains") },
            modifier = Modifier.fillMaxWidth()
                .onFocusChanged { focusState ->
                    if (focusState.isFocused) {
                        copied = 1
                    }
                }
        )

        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(
                enabled = !isRunning,
                selected = (format == "PEM"),
                onClick = { format = "PEM"; copied = 1; keyboardController?.hide()})
            Text("PEM-format", modifier = Modifier.padding(end = 6.dp))

            RadioButton(
                enabled = !isRunning,
                selected = (format == "JWK"),
                onClick = { format = "JWK"; copied = 1; keyboardController?.hide()})
            Text("JWK-format")
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Button(enabled = !isRunning, onClick = {
                keyboardController?.hide()
                copied = 1
                bgjob.launch {
                    val (fullcert, fulldomain) = genCertificate(
                        passwordState.text.toString(),
                        domains.text.toString(), onProgress = { currentProgress -> progress = currentProgress }
                    )
                    certState.edit { replace(0, length, fullcert) }
                    domainState.edit { replace(0, length, fulldomain) }
                }
            }, modifier = Modifier.weight(1f)) {
                Text(
                    if (progress == 0) {
                        "Generate DNS\n and Certificate"
                    } else {
                        "Generating...\n[" + "#".repeat(progress) + "_".repeat(9 - progress) + "]"
                    }, textAlign = TextAlign.Center
                )
            }

            Button(enabled = !isRunning, onClick = {
                keyboardController?.hide()
                copied = 1
                val (fullcert, fulldomain) = genKey(
                    passwordState.text.toString(),
                    domains.text.toString(), format
                )
                certState.edit { replace(0, length, fullcert) }
                domainState.edit { replace(0, length, fulldomain) }
            }, modifier = Modifier.weight(1f)) {
                Text(
                    "Generate TLSA\nKey and CSR",
                    textAlign = TextAlign.Center
                )
            }
        }

        Text(
            "\nTo only generate DNS Record without Certificate, or generate TLSA and Key without CSR, leave \"Domains\" field blank.\nDNS-record to add:",
            style = MaterialTheme.typography.labelLarge
        )

        SelectionContainer {
            TextField(
                state = domainState,
                readOnly = true,
                modifier = Modifier.fillMaxWidth()
                    .onFocusChanged { focusState ->
                        if (focusState.isFocused) {
                                keyboardController?.hide()
                                if (copied != 2) {
                                    val clipData = android.content.ClipData.newPlainText("record", certState.text.toString())
                                    val clipEntry = ClipEntry(clipData)
                                    bgjob.launch {
                                        clipboardManager.setClipEntry(clipEntry)
                                    }
                                     copied = 2
                                }
                            }
                    },
            )
        }

        Text("Certificate or private key:", style = MaterialTheme.typography.labelLarge)
        SelectionContainer {
            TextField(
                textStyle = TextStyle(fontFamily = FontFamily.Monospace),
                state = certState,
                readOnly = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .fillMaxHeight()
                    .onFocusChanged { focusState ->
                        if (focusState.isFocused) {
                                keyboardController?.hide()
                                if (copied != 3) {
                                val clipData = android.content.ClipData.newPlainText("certificate", certState.text.toString())
                                val clipEntry = ClipEntry(clipData)
                                bgjob.launch {
                                    clipboardManager.setClipEntry(clipEntry)
                                }
                                   copied = 3
                                }
                        }
                    }
            )
        }
    }



}

}

    suspend fun genCertificate(passwd: String, domains: String, onProgress: (Int) -> Unit): Pair<String, String> {
        val acmeURL: String = if (staging == 1) {
            "https://acme-staging-v02.api.letsencrypt.org"
        } else {
            "https://acme-v02.api.letsencrypt.org"
        }

        if (passwd.isEmpty()) {
            return Pair("", "The password cannot be empty.")
        }
        if (domains.contains("*")) {
            return Pair("", "Domains cannot contain * - wildcard is included automatically.")
        }
        onProgress(1)
        val dgest = MessageDigest.getInstance("SHA-384")
        val acctpassword = "$passwd-"
        var accounturi: String
        var caadomain: String
        val hashBytes = dgest.digest(acctpassword.toByteArray(Charsets.UTF_8))
        val algoParams = AlgorithmParameters.getInstance("EC")
        algoParams.init(ECGenParameterSpec("secp384r1"))
        val ecSpec = algoParams.getParameterSpec(ECParameterSpec::class.java)
        val keypairprivate = ECPrivateKeySpec(BigInteger(1, hashBytes), ecSpec)
        val kf = KeyFactory.getInstance("EC", "AndroidOpenSSL")
        val ecPrivate = kf.generatePrivate(keypairprivate)
        val json = Json {ignoreUnknownKeys = true; coerceInputValues = true }
        val retrofit = Retrofit.Builder().baseUrl(acmeURL).addConverterFactory(json.asConverterFactory("application/json".toMediaType())).build()
        val api = retrofit.create(AcmeApi::class.java)
        try {
                val directory = api.getDirectory()
                val objNonce = api.blankGet(directory.newNonce)
                nonce = objNonce.headers()["Replay-Nonce"] ?: nonce
                val objAcctCreate = api.blankPost(directory.newAccount, genJWK(directory.newAccount, ecPrivate, "{\"termsOfServiceAgreed\": true}", ""))
                if (objAcctCreate.code() > 399) {
                    onProgress(0)
                    return Pair(
                        "Invalid password",
                        "Failed to access or create account - invalid password?"
                    )
                }
                nonce = objAcctCreate.headers()["Replay-Nonce"] ?: nonce
                accounturi = objAcctCreate.headers()["Location"] ?: ""
                caadomain = directory.meta.caaIdentities[0]
                if (domains.isEmpty()) {
                    onProgress(0)
                    return Pair(
                        "Please add the above DNS record to your DNS, remembering to replace YOURDOMAIN.TLD with your domain",
                        "_validation-persist.YOURDOMAIN.TLD IN TXT \"$caadomain;accounturi=$accounturi;policy=wildcard\""
                    )
                }
                else
                {
                    onProgress(2)
                    val listdomains = domains.split(",").map { it.trim() }.filter { it.isNotEmpty() }.flatMap { listOf(it, "*.$it") }.distinct()
                    val jsonorder = """{"identifiers": [${listdomains.joinToString(",") { """{"type": "dns", "value": "$it"}""" }}]}"""
                    val order = api.getOrder(directory.newOrder, genJWK(directory.newOrder, ecPrivate, jsonorder, accounturi))
                    if (order.code() > 399) {
                        onProgress(0)
                        return Pair(
                            "Unable to create order - did you request certificate for a blacklisted domain?",
                            "_validation-persist.YOURDOMAIN.TLD IN TXT \"$caadomain;accounturi=$accounturi;policy=wildcard\""
                        )
                    }
                    nonce = order.headers()["Replay-Nonce"] ?: nonce
                    val orderuri = order.headers()["Location"] ?: ""
                    for (auth in order.body()!!.authorizations) {
                        onProgress(3)
                        val autz = api.getAutz(auth, genJWK(auth, ecPrivate, "", accounturi ))
                        nonce = autz.headers()["Replay-Nonce"] ?: nonce
                        for (chal in autz.body()!!.challenges) {
                        if (chal.type == "dns-persist-01") {
                          val blpost = api.blankPost(chal.url, genJWK(chal.url, ecPrivate, "{}", accounturi))
                            nonce = blpost.headers()["Replay-Nonce"] ?: nonce
                            break
                        }
                        }
                    }
                    onProgress(4)
                    var ordercheck = api.getOrder(orderuri, genJWK(orderuri, ecPrivate, "", accounturi))
                    nonce = ordercheck.headers()["Replay-Nonce"] ?: nonce
                    while (true) {
                        onProgress(5)
                        delay(1000)
                        ordercheck = api.getOrder(orderuri, genJWK(orderuri, ecPrivate, "", accounturi))
                        nonce = ordercheck.headers()["Replay-Nonce"] ?: nonce
                        if (ordercheck.body()!!.status == "invalid") {
                            onProgress(0)
                            return Pair(
                                "Error validating domains, you have not published the DNS records yet!",
                                "_validation-persist.YOURDOMAIN.TLD IN TXT \"$caadomain;accounturi=$accounturi;policy=wildcard\""
                            )
                        }
                        if (ordercheck.body()!!.status == "ready") {
                            break
                        }
                    }
                    onProgress(6)
                    val hbb = dgest.digest(passwd.toByteArray(Charsets.UTF_8))
                    val kpp = ECPrivateKeySpec(BigInteger(1, hbb), ecSpec)
                    val kfp = KeyFactory.getInstance("EC", "AndroidOpenSSL")
                    val crtprivate = kfp.generatePrivate(kpp)
                    val csrjson = "{\"csr\": \"" + android.util.Base64.encodeToString(genCSR(crtprivate, domains), android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING) + "\"}"
                    val csrresponse = api.blankPost(ordercheck.body()!!.finalize, genJWK(ordercheck.body()!!.finalize, ecPrivate, csrjson , accounturi))
                    if (csrresponse.code() > 399) {
                        onProgress(0)
                        return Pair(
                            "Unable to submit CSR - something in the CSR is wierd?",
                            "_validation-persist.YOURDOMAIN.TLD IN TXT \"$caadomain;accounturi=$accounturi;policy=wildcard\""
                        )
                    }
                    nonce = csrresponse.headers()["Replay-Nonce"] ?: nonce
                    onProgress(7)
                    ordercheck = api.getOrder(orderuri, genJWK(orderuri, ecPrivate, "", accounturi))
                    nonce = ordercheck.headers()["Replay-Nonce"] ?: nonce
                    while (true) {
                        onProgress(8)
                        delay(1000)
                        ordercheck = api.getOrder(orderuri, genJWK(orderuri, ecPrivate, "", accounturi))
                        nonce = ordercheck.headers()["Replay-Nonce"] ?: nonce
                        if (ordercheck.body()!!.status == "invalid") {
                            return Pair(
                                "Error submitting CSR!",
                                "_validation-persist.YOURDOMAIN.TLD IN TXT \"$caadomain;accounturi=$accounturi;policy=wildcard\""
                            )
                        }
                        if (ordercheck.body()!!.status == "valid") {
                            break
                        }
                    }
                    onProgress(9)
                    val pemcertificate = api.fetchcertificate(ordercheck.body()!!.certificate!!, genJWK(ordercheck.body()!!.certificate!!, ecPrivate, "", accounturi))
                    onProgress(0)
                    return Pair(
                        pemcertificate.body()!!.string(),
                        "_validation-persist.YOURDOMAIN.TLD IN TXT \"$caadomain;accounturi=$accounturi;policy=wildcard\""
                    )

                }
            } catch (e: Exception) {
            onProgress(0)
            val sw = StringWriter()
            e.printStackTrace(PrintWriter(sw))
            val exceptionAsString = sw.toString()
            return Pair(exceptionAsString, "Fatal error occurred, are you connected to the internet?")
            }
    }

fun genJWK(url: String, privkey: PrivateKey, payload: String, accounturi: String): RequestBody {
    var header: JWSHeader
    val jwk = ECKey.Builder(Curve.P_384, getPublicKey(privkey))
        .privateKey(privkey as ECPrivateKey)
        .build()
    val jwkFullJson = jwk.toPublicJWK()

    if (accounturi.isNotEmpty()) {
        header = JWSHeader.Builder(JWSAlgorithm.ES384)
            .customParam("nonce", nonce)
            .customParam("url", url)
            .keyID(accounturi)
            .build()
    } else {
        header = JWSHeader.Builder(JWSAlgorithm.ES384)
            .customParam("nonce", nonce)
            .customParam("url", url)
            .jwk(jwkFullJson)
            .build()
    }

    val payload = Payload(payload)
    val jwsObject = JWSObject(header, payload)
    val signer = ECDSASigner(jwk)
    jwsObject.sign(signer)

    val acmeRequestBody = """
{
  "protected": "${jwsObject.header.toBase64URL()}",
  "payload": "${jwsObject.payload.toBase64URL()}",
  "signature": "${jwsObject.signature}"
}
""".trimIndent()

return acmeRequestBody.toRequestBody("application/jose+json".toMediaType())
}

fun genKey(passwd: String, domains: String, format: String): Pair<String, String> {
    if (passwd.isEmpty()) {
        return Pair("", "The password cannot be empty.")
    }
    if (domains.contains("*")) {
        return Pair("", "Domains cannot contain * - wildcard is included automatically.")
    }
    var certState: String
    val dgest = MessageDigest.getInstance("SHA-384")
    val hashBytes = dgest.digest(passwd.toByteArray(Charsets.UTF_8))
    val algoParams = AlgorithmParameters.getInstance("EC")
    algoParams.init(ECGenParameterSpec("secp384r1"))
    val ecSpec = algoParams.getParameterSpec(ECParameterSpec::class.java)
    val keypairprivate = ECPrivateKeySpec(BigInteger(1, hashBytes), ecSpec )
    val kf = KeyFactory.getInstance("EC", "AndroidOpenSSL")
    val eCPrivate = kf.generatePrivate(keypairprivate)
    if (format == "JWK") {
        certState = ECKey.Builder(Curve.P_384, getPublicKey(eCPrivate)).privateKey(eCPrivate as ECPrivateKey).build().toJSONString()
    }
    else {
        certState = if (domains.length < 4) {
            "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(eCPrivate.encoded)
                .chunked(64).joinToString("\n") + "\n-----END PRIVATE KEY-----"
        } else {
            "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(eCPrivate.encoded)
                .chunked(64)
                .joinToString("\n") + "\n-----END PRIVATE KEY-----\n\n-----BEGIN CERTIFICATE REQUEST-----\n" + Base64.getEncoder()
                .encodeToString(genCSR(eCPrivate, domains)).chunked(64)
                .joinToString("\n") + "\n-----END CERTIFICATE REQUEST-----"
        }
    }
    val spkidgest = MessageDigest.getInstance("SHA-256")
    val spkihex = spkidgest.digest(getPublicKey(eCPrivate).encoded).joinToString("") { "%02x".format(it) }
    return Pair(certState, "_PORT._tcp.YOURDOMAIN.TLD IN TLSA 3 1 1 $spkihex")
}

fun genCSR(privateKey: PrivateKey, domainString: String): ByteArray {
    val domains = domainString.split(",").map { it.trim() }.filter { it.isNotEmpty() }
    val mainDomain = domains.first()
    val dnInner = "06035504030c" + toAsn1Hex(mainDomain.toByteArray())
    val dn = wrap("30", wrap("31", wrap("30", dnInner)))
    var sansHex = ""
    for (d in domains) {
        sansHex += "82" + toAsn1Hex(d.toByteArray())
        sansHex += "82" + toAsn1Hex("*.$d".toByteArray())
    }
    var extensionRequest = wrap("30", sansHex)
    extensionRequest = "0603551d1104" + toAsn1Hex(hexToByteArray(extensionRequest))
    extensionRequest = wrap("30", extensionRequest)
    extensionRequest = wrap("30", extensionRequest)
    extensionRequest = "06092a864886f70d01090e31" + toAsn1Hex(hexToByteArray(extensionRequest))
    extensionRequest = wrap("30", extensionRequest)
    val attributes = wrap("a0", extensionRequest)
    val spkiHeader = "3076301006072a8648ce3d020106052b81040022036200"
    val pubKeyHex = bytesToHex(getPublicKey(privateKey).w.affineX.toPaddedByteArray(48)) +
            bytesToHex(getPublicKey(privateKey).w.affineY.toPaddedByteArray(48))
    val spki = spkiHeader + "04" + pubKeyHex
    val version = "020100"
    val tbsDataHex = wrap("30", version + dn + spki + attributes)
    val tbsData = hexToByteArray(tbsDataHex)
    val sigInstance = Signature.getInstance("SHA384withECDSA")
    sigInstance.initSign(privateKey)
    sigInstance.update(tbsData)
    val signature = sigInstance.sign()
    val algoId = "300a06082a8648ce3d040303"
    val signatureBitString = "03" + toAsn1Hex(byteArrayOf(0) + signature) // 0 padding bits
    val finalCsrHex = wrap("30", tbsDataHex + algoId + signatureBitString)
    return hexToByteArray(finalCsrHex)
}


private fun wrap(tag: String, hexContent: String): String {
    return tag + getAsn1Length(hexContent.length / 2) + hexContent
}

private fun toAsn1Hex(bytes: ByteArray): String {
    return getAsn1Length(bytes.size) + bytesToHex(bytes)
}

private fun getAsn1Length(len: Int): String {
    if (len <= 127) return String.format("%02x", len)
    val hexLen = Integer.toHexString(len)
    val finalHex = if (hexLen.length % 2 != 0) "0$hexLen" else hexLen
    return String.format("%02x", 0x80 or (finalHex.length / 2)) + finalHex
}

private fun BigInteger.toPaddedByteArray(n: Int): ByteArray {
    val bytes = this.toByteArray()
    val stripped = if (bytes.size > 1 && bytes[0] == 0.toByte()) {
        bytes.copyOfRange(1, bytes.size)
    } else {
        bytes
    }
    return when {
        stripped.size >= n -> stripped.takeLast(n).toByteArray()
        else -> ByteArray(n - stripped.size) + stripped
    }
}

private fun bytesToHex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
private fun hexToByteArray(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

fun getPublicKey(privateKey: PrivateKey): ECPublicKey {
    val priv = privateKey as ECPrivateKey
    val s = priv.s
    val params = priv.params
    val field = params.curve.field as ECFieldFp
    val p = field.p
    val a = params.curve.a
    val g = params.generator

    var resX: BigInteger? = null
    var resY: BigInteger? = null
    var tempX = g.affineX
    var tempY = g.affineY

    for (i in 0 until s.bitLength()) {
        if (s.testBit(i)) {
            if (resX == null) {
                resX = tempX
                resY = tempY
            } else {
                val added = ecAdd(resX, resY!!, tempX, tempY, p, a)
                resX = added.first
                resY = added.second
            }
        }
        val doubled = ecAdd(tempX, tempY, tempX, tempY, p, a)
        tempX = doubled.first
        tempY = doubled.second
    }

    val pubSpec = ECPublicKeySpec(ECPoint(resX!!, resY!!), params)
    return KeyFactory.getInstance("EC").generatePublic(pubSpec) as ECPublicKey
}

private fun ecAdd(x1: BigInteger, y1: BigInteger, x2: BigInteger, y2: BigInteger, p: BigInteger, a: BigInteger): Pair<BigInteger, BigInteger> {
    val lambda = if (x1 == x2 && y1 == y2) {
        val num = x1.pow(2).multiply(3.toBigInteger()).add(a)
        val den = y1.multiply(2.toBigInteger()).modInverse(p)
        num.multiply(den).mod(p)
    } else {
        val num = y2.subtract(y1)
        val den = x2.subtract(x1).modInverse(p)
        num.multiply(den).mod(p)
    }

    val x3 = lambda.pow(2).subtract(x1).subtract(x2).mod(p)
    val y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p)
    return x3 to y3
}


@Preview(showBackground = true)
@Composable
fun AcmeFormPreview() {
    AcmenostateTheme {
        AcmeForm()
    }
}
