package eu.sebbe.acme_nostate

import android.os.Bundle
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
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.TextField
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.StringWriter
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
import java.util.Base64
import java.security.PublicKey
import kotlinx.serialization.Serializable
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import retrofit2.Retrofit
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Body
import retrofit2.http.Path
import retrofit2.http.Url
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

@Serializable
data class Directory(
    val newNonce: String,
    val newAccount: String,
    val newOrder: String,
    val meta: Meta
)

@Serializable
data class Meta(
    val caaIdentities: List<String>
)

@Serializable
data class Order(
    val status: String,
    val authorizations: List<String>,
    val finalize: String,
    val certificate: String?
)

@Serializable
data class Autz(
    val challenges: List<Chal>
)

@Serializable
data class Chal(
    val url: String,
    val type: String
)


interface AcmeApi {
    @GET("directory")
    suspend fun getDirectory(): Directory

    @GET
    suspend fun getOrder(@Url url: String): Order

    @GET
    suspend fun getAutz(@Url url: String): Autz
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


@Composable
fun AcmenostateTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color is available on Android 12+
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
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    AcmeForm(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

@Composable
fun AcmeForm(modifier: Modifier = Modifier) {
    val keyboardController = LocalSoftwareKeyboardController.current
    val domains = rememberTextFieldState()
    var format by remember { mutableStateOf("PEM") }
    val passwordState = rememberTextFieldState()
    val domainState = rememberTextFieldState()
    val certState = rememberTextFieldState()

    var showPassword by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        SecureTextField(
            state = passwordState,
            label = { Text("Password") },
            textObfuscationMode = if (showPassword) {
                TextObfuscationMode.Visible
            } else {
                TextObfuscationMode.RevealLastTyped
            },
            modifier = Modifier.fillMaxWidth(),
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        imageVector = if (showPassword) Icons.Filled.Visibility else Icons.Filled.VisibilityOff,
                        contentDescription = if (showPassword) "Hide password" else "Show password"
                    )
                }
            }
        )
        TextField(
            state = domains,
            label = { Text("Domains") },
            modifier = Modifier.fillMaxWidth()
        )

        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = (format == "PEM"), onClick = { format = "PEM" })
            Text("PEM-format", modifier = Modifier.padding(end = 16.dp))

            RadioButton(selected = (format == "JWK"), onClick = { format = "JWK" })
            Text("JWK-format")
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(onClick = { keyboardController?.hide()
                val (fullcert, fulldomain) = genCertificate(passwordState.text.toString(), domains.text.toString())
                certState.edit { replace(0, length, fullcert) }
                domainState.edit { replace(0, length, fulldomain) }}, modifier = Modifier.weight(1f)) {
                Text("Generate DNS\n and Certificate", textAlign = TextAlign.Center)
            }
                Button(onClick = {
                    keyboardController?.hide()
                    val (fullcert, fulldomain) = genKey(
                        passwordState.text.toString(),
                        domains.text.toString()
                    )
                    certState.edit { replace(0, length, fullcert) }
                    domainState.edit { replace(0, length, fulldomain) }
                }, modifier = Modifier.weight(1f)) {
                    Text(
                        "Generate Key\n and CSR",
                        textAlign = TextAlign.Center
                    )
                }
        }

        Text("\nTo only generate DNS Record without Certificate, or generate Private Key without CSR, leave \"Domains\" field blank.\n", style = MaterialTheme.typography.labelLarge)

        Text("DNS-record to add:", style = MaterialTheme.typography.labelLarge)
        SelectionContainer {
            TextField(
                state = domainState,
                readOnly = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Text("Certificate or private key:", style = MaterialTheme.typography.labelLarge)
        SelectionContainer {
            TextField(
                state = certState,
                readOnly = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .fillMaxHeight()
            )
        }
    }
}

fun genCertificate(passwd: String, domains: String): Pair<String, String>  {
    if (passwd.isEmpty()) {
        return Pair("", "The password cannot be empty.")
    }
    val dgest = MessageDigest.getInstance("SHA-384")
    val acctpassword = "$passwd-"
    val hashBytes = dgest.digest(acctpassword.toByteArray(Charsets.UTF_8))
    val algoParams = AlgorithmParameters.getInstance("EC")
    algoParams.init(ECGenParameterSpec("secp384r1"))
    val ecSpec = algoParams.getParameterSpec(ECParameterSpec::class.java)
    val keypairprivate = ECPrivateKeySpec(BigInteger(1, hashBytes), ecSpec )
    val kf = KeyFactory.getInstance("EC", "AndroidOpenSSL")
    val ecPrivate = kf.generatePrivate(keypairprivate)
    val ecPublic = getPublicKey(ecPrivate)


return Pair("","")
}

fun genKey(passwd: String, domains: String): Pair<String, String> {
    if (passwd.isEmpty()) {
        return Pair("", "The password cannot be empty.")
    }
    val dgest = MessageDigest.getInstance("SHA-384")
    val hashBytes = dgest.digest(passwd.toByteArray(Charsets.UTF_8))
    val algoParams = AlgorithmParameters.getInstance("EC")
    algoParams.init(ECGenParameterSpec("secp384r1"))
    val ecSpec = algoParams.getParameterSpec(ECParameterSpec::class.java)
    val keypairprivate = ECPrivateKeySpec(BigInteger(1, hashBytes), ecSpec )
    val kf = KeyFactory.getInstance("EC", "AndroidOpenSSL")
    val eCPrivate = kf.generatePrivate(keypairprivate)
    val certState: String = if (domains.length < 4) {
        "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(eCPrivate.encoded).chunked(64).joinToString("\n") + "\n-----END PRIVATE KEY-----"
    }
    else
    {
        "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(eCPrivate.encoded).chunked(64).joinToString("\n") + "\n-----END PRIVATE KEY-----\n\n" + genCSR(eCPrivate, domains)
    }
    return Pair(certState, "")
}

fun genCSR(privateKey: PrivateKey, domainString: String): String {
    val domains = domainString.split(",").map { it.trim() }.filter { it.isNotEmpty() }.flatMap { listOf(it, "*.$it") }.distinct()
    val mainDomain = domains.first()
    val entityName = X500Name("CN=$mainDomain")
    val csrBuilder = JcaPKCS10CertificationRequestBuilder(entityName, getPublicKey(privateKey))
    val altNames = domains.map { GeneralName(GeneralName.dNSName, it) }.toTypedArray()
    val subjectAltNames = GeneralNames(altNames)
    val extGen = ExtensionsGenerator()
    extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames)
    csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())

    val signer = object : ContentSigner {
        private val outputStream = ByteArrayOutputStream()
        private val bcParam = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil.generatePrivateKeyParameter(privateKey)
        private val engine = ECDSASigner(HMacDSAKCalculator(SHA384Digest())).apply {
            init(true, bcParam)
        }
        override fun getAlgorithmIdentifier(): AlgorithmIdentifier =
            AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA384)
        override fun getOutputStream(): OutputStream = outputStream
        override fun getSignature(): ByteArray {
            val hash = ByteArray(SHA384Digest().digestSize)
            val content = outputStream.toByteArray()
            SHA384Digest().update(content, 0, content.size)
            SHA384Digest().doFinal(hash, 0)
            val sig = engine.generateSignature(hash)
            return org.bouncycastle.asn1.DERSequence(arrayOf(
                org.bouncycastle.asn1.ASN1Integer(sig[0]),
                org.bouncycastle.asn1.ASN1Integer(sig[1])
            )).encoded
        }
    }

    val csr = csrBuilder.build(signer)
    val sw = StringWriter()
    PemWriter(sw).use { it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded)) }
    return sw.toString()
}
fun getPublicKey(privateKey: PrivateKey): PublicKey {
    val kf = KeyFactory.getInstance("EC")
    val privSpec = kf.getKeySpec(privateKey, ECPrivateKeySpec::class.java)
    val s = privSpec.s
    val bcParams = ECNamedCurveTable.getParameterSpec("secp384r1")
    val q = bcParams.g.multiply(s).normalize()
    val ecSpec = ECNamedCurveSpec("secp384r1", bcParams.curve, bcParams.g, bcParams.n)
    val pubSpec = ECPublicKeySpec(
        ECPoint(q.affineXCoord.toBigInteger(), q.affineYCoord.toBigInteger()),
        ecSpec
    )
    return kf.generatePublic(pubSpec)
}


@Preview(showBackground = true)
@Composable
fun AcmeFormPreview() {
    AcmenostateTheme {
        AcmeForm()
    }
}
