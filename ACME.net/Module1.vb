Imports System.IO
Imports System.Runtime.InteropServices
Imports System.Runtime.Serialization
Imports System.Runtime.Serialization.Json
Imports System.Security.Cryptography
Imports System.Security.Cryptography.X509Certificates
Imports System.Text
Imports System.Linq

Module Module1
    <DllImport("kernel32.dll", EntryPoint:="AttachConsole", SetLastError:=True)>
    Private Function ConnectToConsole(dwProcessId As Integer) As Boolean
    End Function


    <DllImport("kernel32.dll", EntryPoint:="FreeConsole", SetLastError:=True)>
    Private Function DoConsole() As Boolean
    End Function

    Sub Main()
        Dim args As String() = Environment.GetCommandLineArgs()
        If args.Length > 1 Then
            Dim resultarray() As String
            ConnectToConsole(-1)

            If args(1).Length < 1 Then
                Console.WriteLine("Password cannot be blank. Use a secure password so nobody guess your private key.")
                Environment.Exit(1)
                Exit Sub
            End If
            If args.Length < 3 Then
                'No filename specified, user wants the DNS-PERSIST-01 record
                resultarray = GenerateCert(args(1), "", Nothing).GetAwaiter.GetResult()
                Console.WriteLine(resultarray(0))
                Environment.Exit(0)
                Exit Sub
            End If
            If (args(3) = "export") Then
                File.WriteAllBytes(args(2), Encoding.UTF8.GetBytes(GenerateKeyAndCSR(args(1), "")(0)))
                Console.WriteLine("Written private key to " & args(2))
                Environment.Exit(0)
                Exit Sub
            End If
            Dim domains = args.Skip(3)
            Dim domainString As String = String.Join(",", domains)
            resultarray = GenerateCert(args(1), domainString, Nothing).GetAwaiter.GetResult()
            If (resultarray(1).Contains("-----BEGIN CERTIFICATE-----")) Then
                File.WriteAllBytes(args(2), Encoding.UTF8.GetBytes(resultarray(1)))
                Console.WriteLine("Successfully generated LE certificate!")
                Environment.Exit(0)
                Exit Sub
            Else
                Console.WriteLine(resultarray(1))
                Environment.Exit(1)
                Exit Sub
            End If
            SendKeys.SendWait("{ENTER}")
        Else
            DoConsole()
            Application.EnableVisualStyles()
            Application.SetCompatibleTextRenderingDefault(False)
            Application.Run(New Form1())
        End If
    End Sub


    Public Async Function GenerateCert(password As String, domains As String, progress As IProgress(Of Integer)) As Task(Of String())
        Dim returnvalue(2) As String

        Try
            Dim alldomains() As String
            Dim staging As Integer
            staging = 1
            Dim ServerURL As String
            If staging = 1 Then
                ServerURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
            Else
                ServerURL = "https://acme-v02.api.letsencrypt.org/directory"
            End If
            returnvalue(0) = ""
            returnvalue(1) = ""

            If progress IsNot Nothing Then
                progress.Report(1)
            End If

            Dim dsa_acct As ECDsa = GenPrivKey(password & "-")
            Dim browser As New Net.Http.HttpClient
            Dim result As MemoryStream
            Dim accounturi As String

            ' Fetch the directory from ACME server.

            result = New MemoryStream(System.Text.Encoding.UTF8.GetBytes(Await browser.GetStringAsync(ServerURL)))
            Dim ser As New DataContractJsonSerializer(GetType(ACMEDirectory))
            Dim serverdirectory As ACMEDirectory = DirectCast(ser.ReadObject(result), ACMEDirectory)

            ' Get a fresh nonce

            If progress IsNot Nothing Then
                progress.Report(2)
            End If

            Dim currentnonce As String
            currentnonce = (Await browser.GetAsync(serverdirectory.Newnonce)).Headers.GetValues("Replay-Nonce").FirstOrDefault()

            ' Create (or access) account
            If progress IsNot Nothing Then
                progress.Report(3)
            End If


            Dim x As String = System.Convert.ToBase64String(dsa_acct.ExportParameters(False).Q.X).Replace("+", "-").Replace("/", "_").Replace("=", "")
            Dim y As String = System.Convert.ToBase64String(dsa_acct.ExportParameters(False).Q.Y).Replace("+", "-").Replace("/", "_").Replace("=", "")
            Dim jwkobject As String = """jwk"": {""kty"": ""EC"", ""crv"": ""P-384"", ""x"": """ & x & """, ""y"": """ & y & """}"
            Dim jwkheader As String = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", " & jwkobject & ", ""nonce"": """ & currentnonce & """, ""url"": """ & serverdirectory.Newaccount & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
            Dim jwkpayload As String = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""termsOfServiceAgreed"": true}"))
            Dim jwksignature As String = System.Convert.ToBase64String(dsa_acct.SignData(System.Text.Encoding.UTF8.GetBytes(jwkheader & "." & jwkpayload), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")

            Dim PostContent As New Net.Http.StringContent("{""protected"": """ & jwkheader & """, ""payload"": """ & jwkpayload & """, ""signature"": """ & jwksignature & """}", System.Text.Encoding.UTF8, "application/jose+json")
            PostContent.Headers.ContentType.CharSet = Nothing
            Dim responsemess = New Net.Http.HttpResponseMessage

            responsemess = Await browser.PostAsync(serverdirectory.Newaccount, PostContent)

            If (responsemess.StatusCode > 399) Then
                returnvalue(1) = "Failed creating account - invalid password?"
                Return returnvalue
            End If

            currentnonce = responsemess.Headers.GetValues("Replay-Nonce").FirstOrDefault()
            accounturi = responsemess.Headers.Location.OriginalString
            returnvalue(0) = "_validation-persist.YOURDOMAIN.TLD IN TXT """ & serverdirectory.Caadomain & ";accounturi=" & accounturi & ";policy=wildcard"""
            If (domains.Length > 3) Then
                Dim orderuri As String

                If progress IsNot Nothing Then
                    progress.Report(4)
                End If

                ' create certificate order
                jwkpayload = "{""identifiers"": ["
                alldomains = domains.Split(",")
                For Each item In alldomains
                    If (item.Length > 0) Then
                        jwkpayload = jwkpayload & "{""type"": ""dns"", ""value"": """ & item & """},{""type"": ""dns"", ""value"": ""*." & item & """},"
                    End If
                Next
                jwkpayload = jwkpayload.Substring(0, jwkpayload.Length - 1)
                jwkpayload = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(jwkpayload & "]}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
                jwkheader = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", ""kid"": """ & accounturi & """, ""nonce"": """ & currentnonce & """, ""url"": """ & serverdirectory.Neworder & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
                jwksignature = System.Convert.ToBase64String(dsa_acct.SignData(System.Text.Encoding.UTF8.GetBytes(jwkheader & "." & jwkpayload), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")
                PostContent = New Net.Http.StringContent("{""protected"": """ & jwkheader & """, ""payload"": """ & jwkpayload & """, ""signature"": """ & jwksignature & """}", System.Text.Encoding.UTF8, "application/jose+json")
                PostContent.Headers.ContentType.CharSet = Nothing
                responsemess = Await browser.PostAsync(serverdirectory.Neworder, PostContent)

                If (responsemess.StatusCode > 399) Then
                    returnvalue(1) = "Failed creating order - blacklisted domains in domain field?"
                    Return returnvalue
                End If

                currentnonce = responsemess.Headers.GetValues("Replay-Nonce").FirstOrDefault()
                orderuri = responsemess.Headers.Location.OriginalString

                result = New MemoryStream(System.Text.Encoding.UTF8.GetBytes(Await responsemess.Content.ReadAsStringAsync()))
                ser = New DataContractJsonSerializer(GetType(ACMEOrders))
                Dim acmeorder As ACMEOrders = DirectCast(ser.ReadObject(result), ACMEOrders)


                If progress IsNot Nothing Then
                    progress.Report(5)
                End If

                ' Submit the DNS-PERSIST-01 challenge for all authorization. Since the DNS-PERSIST-01 record should be pre-provisioned, we dont need to pause execution to let the user publish

                For Each item In acmeorder.Authorizations
                    currentnonce = Await SubmitChallenge(dsa_acct, item, currentnonce, accounturi)
                Next

                ' Wait until Lets Encrypt server finishes the validations.
                If progress IsNot Nothing Then
                    progress.Report(6)
                End If


                Dim orderarray() As String = Await CheckOrder(dsa_acct, orderuri, currentnonce, accounturi)
                Do Until orderarray(1) = "ready"
                    currentnonce = orderarray(0)
                    Await Task.Delay(1000)
                    orderarray = Await CheckOrder(dsa_acct, orderuri, currentnonce, accounturi)
                    If (orderarray(1) = "invalid") Then
                        returnvalue(1) = "Failed validation, you haven't published the DNS records yet!"
                        Return returnvalue
                    End If
                Loop


                If progress IsNot Nothing Then
                    progress.Report(7)
                End If

                ' Submit CSR to Lets encrypt server

                currentnonce = orderarray(0)
                jwkpayload = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""csr"": """ & System.Convert.ToBase64String(GenCSR(password, domains)).Replace("+", "-").Replace("/", "_").Replace("=", "") & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
                jwkheader = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", ""kid"": """ & accounturi & """, ""nonce"": """ & currentnonce & """, ""url"": """ & orderarray(2) & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
                jwksignature = System.Convert.ToBase64String(dsa_acct.SignData(System.Text.Encoding.UTF8.GetBytes(jwkheader & "." & jwkpayload), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")
                PostContent = New Net.Http.StringContent("{""protected"": """ & jwkheader & """, ""payload"": """ & jwkpayload & """, ""signature"": """ & jwksignature & """}", System.Text.Encoding.UTF8, "application/jose+json")
                PostContent.Headers.ContentType.CharSet = Nothing
                responsemess = Await browser.PostAsync(orderarray(2), PostContent)
                currentnonce = responsemess.Headers.GetValues("Replay-Nonce").FirstOrDefault()

                If (responsemess.StatusCode > 399) Then
                    returnvalue(1) = "Server rejected CSR!"
                    Return returnvalue
                End If


                If progress IsNot Nothing Then
                    progress.Report(8)
                End If

                ' Wait until certificate is generated

                Do Until orderarray(1) = "valid"
                    currentnonce = orderarray(0)
                    Await Task.Delay(1000)
                    orderarray = Await CheckOrder(dsa_acct, orderuri, currentnonce, accounturi)
                    If (orderarray(1) = "invalid") Then
                        returnvalue(1) = "Failed csr submit - something in the CSR was malformed!"
                        Return returnvalue
                    End If
                Loop
                currentnonce = orderarray(0)


                If progress IsNot Nothing Then
                    progress.Report(9)
                End If

                ' Fetch the certificate

                jwkheader = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", ""kid"": """ & accounturi & """, ""nonce"": """ & currentnonce & """, ""url"": """ & orderarray(3) & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
                jwksignature = System.Convert.ToBase64String(dsa_acct.SignData(System.Text.Encoding.UTF8.GetBytes(jwkheader & "."), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")
                PostContent = New Net.Http.StringContent("{""protected"": """ & jwkheader & """, ""payload"": """", ""signature"": """ & jwksignature & """}", System.Text.Encoding.UTF8, "application/jose+json")
                PostContent.Headers.ContentType.CharSet = Nothing

                responsemess = Await browser.PostAsync(orderarray(3), PostContent)
                returnvalue(1) = (Await responsemess.Content.ReadAsStringAsync()).Replace(vbCrLf, vbLf).Replace(vbLf, vbCrLf)

            End If
            Return returnvalue

        Catch ex As Exception
            returnvalue(0) = ""
            returnvalue(1) = "An error occured. Propably you lack internet connection or other similiar unhandled error. Try connecting to internet."
            Return returnvalue
        End Try
    End Function


    Public Async Function CheckOrder(privatekey As ECDsa, orderuri As String, nonce As String, accounturi As String) As Task(Of String())
        Dim returndata(3) As String
        returndata(0) = ""
        returndata(1) = ""
        returndata(2) = ""
        returndata(3) = ""
        Dim browser As New Net.Http.HttpClient
        Dim pgres = New Net.Http.HttpResponseMessage
        Dim jwkh As String = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", ""kid"": """ & accounturi & """, ""nonce"": """ & nonce & """, ""url"": """ & orderuri & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
        Dim jwks As String = System.Convert.ToBase64String(privatekey.SignData(System.Text.Encoding.UTF8.GetBytes(jwkh & "."), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")
        Dim postasget As Net.Http.StringContent = New Net.Http.StringContent("{""protected"": """ & jwkh & """, ""payload"": """", ""signature"": """ & jwks & """}", System.Text.Encoding.UTF8, "application/jose+json")
        postasget.Headers.ContentType.CharSet = Nothing
        pgres = Await browser.PostAsync(orderuri, postasget)
        nonce = pgres.Headers.GetValues("Replay-Nonce").FirstOrDefault()

        Dim chal As MemoryStream = New MemoryStream(System.Text.Encoding.UTF8.GetBytes(Await pgres.Content.ReadAsStringAsync()))
        Dim chals As DataContractJsonSerializer = New DataContractJsonSerializer(GetType(ACMEOrders))
        Dim acmeorder As ACMEOrders = DirectCast(chals.ReadObject(chal), ACMEOrders)

        returndata(0) = nonce
        returndata(1) = acmeorder.Status
        returndata(2) = acmeorder.Newfinalize
        If (acmeorder.Status = "valid") Then
            returndata(3) = acmeorder.Certificate
        End If
        Return returndata
    End Function



    Public Async Function SubmitChallenge(privatekey As ECDsa, autzurl As String, nonce As String, accounturi As String) As Task(Of String)
        Dim browser As New Net.Http.HttpClient
        Dim pgres = New Net.Http.HttpResponseMessage
        Dim jwkh As String = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", ""kid"": """ & accounturi & """, ""nonce"": """ & nonce & """, ""url"": """ & autzurl & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
        Dim jwks As String = System.Convert.ToBase64String(privatekey.SignData(System.Text.Encoding.UTF8.GetBytes(jwkh & "."), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")
        Dim postasget As Net.Http.StringContent = New Net.Http.StringContent("{""protected"": """ & jwkh & """, ""payload"": """", ""signature"": """ & jwks & """}", System.Text.Encoding.UTF8, "application/jose+json")
        postasget.Headers.ContentType.CharSet = Nothing
        pgres = Await browser.PostAsync(autzurl, postasget)
        nonce = pgres.Headers.GetValues("Replay-Nonce").FirstOrDefault()

        Dim chal As MemoryStream = New MemoryStream(System.Text.Encoding.UTF8.GetBytes(Await pgres.Content.ReadAsStringAsync()))
        Dim chals As DataContractJsonSerializer = New DataContractJsonSerializer(GetType(ACMEAuthorization))
        Dim acmeautz As ACMEAuthorization = DirectCast(chals.ReadObject(chal), ACMEAuthorization)

        For Each item In acmeautz.Challenges
            If (item.Type.ToLower = "dns-persist-01") Then
                jwkh = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{""alg"": ""ES384"", ""kid"": """ & accounturi & """, ""nonce"": """ & nonce & """, ""url"": """ & item.Url & """}")).Replace("+", "-").Replace("/", "_").Replace("=", "")
                jwks = System.Convert.ToBase64String(privatekey.SignData(System.Text.Encoding.UTF8.GetBytes(jwkh & ".e30"), HashAlgorithmName.SHA384)).Replace("+", "-").Replace("/", "_").Replace("=", "")
                postasget = New Net.Http.StringContent("{""protected"": """ & jwkh & """, ""payload"": ""e30"", ""signature"": """ & jwks & """}", System.Text.Encoding.UTF8, "application/jose+json")
                postasget.Headers.ContentType.CharSet = Nothing
                pgres = Await browser.PostAsync(item.Url, postasget)
                nonce = pgres.Headers.GetValues("Replay-Nonce").FirstOrDefault()
                Exit For
            End If
        Next
        Return nonce
    End Function


    Public Function GenerateKeyAndCSR(password As String, domains As String) As String()
        Dim sha384hash As SHA384 = SHA384.Create()
        Dim returnvalue(2) As String
        returnvalue(0) = ""
        returnvalue(1) = ""
        Dim header As Byte() = {&H30, &H3E, &H2, &H1, &H1, &H4, &H30}
        Dim footer As Byte() = {&HA0, &H7, &H6, &H5, &H2B, &H81, &H4, &H0, &H22}
        returnvalue(0) = "-----BEGIN EC PRIVATE KEY-----" & Environment.NewLine & System.Convert.ToBase64String(header.Concat(sha384hash.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password))).Concat(footer).ToArray(), Base64FormattingOptions.InsertLineBreaks) & Environment.NewLine & "-----END EC PRIVATE KEY-----"
        returnvalue(0) = returnvalue(0).Replace(vbCrLf, vbLf).Replace(vbLf, vbCrLf)
        If (domains.Length > 3) And (Not domains.Contains("*")) Then
            returnvalue(1) = "-----BEGIN CERTIFICATE REQUEST-----" & Environment.NewLine & System.Convert.ToBase64String(GenCSR(password, domains), Base64FormattingOptions.InsertLineBreaks) & Environment.NewLine & "-----END CERTIFICATE REQUEST-----"
            returnvalue(1) = returnvalue(1).Replace(vbCrLf, vbLf).Replace(vbLf, vbCrLf)
        End If
        Return returnvalue
    End Function


    Public Function GenCSR(password As String, domains As String) As Byte()
        Dim alldomains() As String
        Dim firstdomain As String
        firstdomain = ""
        Dim sanBuilder As New SubjectAlternativeNameBuilder()
        Dim dsa As ECDsa = GenPrivKey(password)
        alldomains = domains.Split(",")
            For Each item In alldomains
                If (firstdomain.Length < 1) And (item.Length > 2) Then
                    firstdomain = item
                End If
                If Not String.IsNullOrWhiteSpace(item.Trim) Then
                    sanBuilder.AddDnsName(item.Trim)
                    sanBuilder.AddDnsName("*." & item.Trim)
                End If
            Next
        Dim subjectName As New X500DistinguishedName("CN=" & firstdomain)
        Dim csr As New CertificateRequest(subjectName, dsa, HashAlgorithmName.SHA384)
        csr.CertificateExtensions.Add(sanBuilder.Build())
        Return csr.CreateSigningRequest
    End Function


    Public Function GenPrivKey(password As String) As ECDsa

        Dim sha384hash As SHA384 = SHA384.Create()
        Dim Dbytes As Byte() = sha384hash.ComputeHash(Encoding.UTF8.GetBytes(password))

        ' Create a blank public key. ECDsa will generate the right public key from the private key, which is generated from the password as random data.
        Dim Xbytes As Byte() = {&H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0}
        Dim Ybytes As Byte() = {&H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0}

        Dim ECParams As New ECParameters With {
        .Curve = ECCurve.NamedCurves.nistP384,
        .D = Dbytes,
        .Q = New ECPoint With {
                .X = Xbytes,
                .Y = Ybytes
            }
        }

        Return ECDsa.Create(ECParams)
    End Function


    <DataContract>
    Public Class ACMEDirectory
        <DataMember(Name:="newNonce")> Public Property Newnonce As String
        <DataMember(Name:="newAccount")> Public Property Newaccount As String
        <DataMember(Name:="newOrder")> Public Property Neworder As String
        <DataMember(Name:="meta")> Public Property Meta As AcmeMeta
        Public ReadOnly Property Caadomain As String
            Get
                Return Meta.Caaidentities(0)
            End Get
        End Property
    End Class


    <DataContract>
    Public Class ACMEAuthorization
        <DataMember(Name:="challenges")> Public Property Challenges As ACMEChallenges()
    End Class

    <DataContract>
    Public Class ACMEChallenges
        <DataMember(Name:="type")> Public Property Type As String
        <DataMember(Name:="url")> Public Property Url As String
    End Class

    <DataContract>
    Public Class ACMEOrders
        <DataMember(Name:="status")> Public Property Status As String
        <DataMember(Name:="authorizations")> Public Property Authorizations As String()
        <DataMember(Name:="finalize")> Public Property Newfinalize As String
        <DataMember(Name:="certificate")> Public Property Certificate As String

    End Class

    <DataContract>
    Public Class AcmeMeta
        <DataMember(Name:="caaIdentities")> Public Property Caaidentities As String()
    End Class


End Module
