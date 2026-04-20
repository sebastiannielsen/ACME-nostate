
Imports System.IO
Imports System.Security.Cryptography
Imports System.Security.Cryptography.X509Certificates
Imports System.Text
Imports System.Text.RegularExpressions

Public Class Form1

    Dim lastcertificate As String
    Dim lastpassword As String

    Private Sub Button2_Click(sender As Object, e As EventArgs) Handles Button2.Click
        Dim returnedcontent As String() = {}
        If TextBox1.Text.Length < 1 Then
            MsgBox("Password cannot be blank. Use a secure password so nobody guess your private key.", vbInformation, "Blank password")
        Else
            returnedcontent = GenerateKeyAndCSR(TextBox1.Text, TextBox2.Text)
            TextBox4.Text = returnedcontent(0) & Environment.NewLine & Environment.NewLine & returnedcontent(1)
        End If

    End Sub

    Private Async Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        Dim returnedcontent As String() = {}
        If TextBox1.Text.Length < 1 Then
            MsgBox("Password cannot be blank. Use a secure password so nobody guess your private key.", vbInformation, "Blank password")
        Else
            TextBox3.Text = ""
            TextBox4.Text = ""
            Button1.Enabled = False
            Button2.Enabled = False
            Button3.Enabled = False
            TextBox1.Enabled = False
            TextBox2.Enabled = False
            Button1.Text = "Generating Certificate..." & Environment.NewLine & "[_________]"

            Dim progressHandler = New Progress(Of Integer)(Sub(value)
                                                               Button1.Text = "Generating Certificate..." & Environment.NewLine & "[" & New String("#"c, value).PadRight(9, "_"c) & "]"
                                                           End Sub)

            returnedcontent = Await GenerateCert(TextBox1.Text, TextBox2.Text, progressHandler)
            Button1.Text = "Generate DNS" & Environment.NewLine & "or Certificate"
            TextBox1.Enabled = True
            TextBox2.Enabled = True
            Button1.Enabled = True
            Button2.Enabled = True
            Button3.Enabled = True
            TextBox3.Text = returnedcontent(0)
            TextBox4.Text = returnedcontent(1)
            If (returnedcontent(1).Contains("-----BEGIN CERTIFICATE-----")) Then
                lastcertificate = returnedcontent(1)
                lastpassword = TextBox1.Text
            End If

        End If
    End Sub


    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles Me.Load
        Button3.Text = ChrW(&HE105) & " Save"
    End Sub

    Private Sub Button3_Click(sender As Object, e As EventArgs) Handles Button3.Click
        If lastcertificate.Contains("-----BEGIN CERTIFICATE-----") Then
            If SaveFileDialog1.ShowDialog() = DialogResult.OK Then
                If SaveFileDialog1.FilterIndex = 3 Then
                    Writep12(lastcertificate, lastpassword, SaveFileDialog1.FileName)
                Else
                    If SaveFileDialog1.FilterIndex = 2 Then
                        Dim pattern As String = "-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"
                        Dim matches = Regex.Matches(lastcertificate, pattern)
                        Dim b64data As String = Regex.Replace(matches(0).Value, "-----BEGIN CERTIFICATE-----", "")
                        b64data = Regex.Replace(b64data, "-----END CERTIFICATE-----", "")
                        File.WriteAllBytes(SaveFileDialog1.FileName, System.Convert.FromBase64String(b64data))
                    Else
                        File.WriteAllBytes(SaveFileDialog1.FileName, Encoding.UTF8.GetBytes(lastcertificate))
                    End If
                End If
            End If
        Else
            MsgBox("No certificate has been generated yet.", vbInformation)
        End If

    End Sub
    Private Sub Writep12(certificates As String, password As String, savepath As String)
        Dim privkey As ECDsa
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
        privkey = ECDsa.Create(ECParams)
        Dim collection As New X509Certificate2Collection()
        Dim pattern As String = "-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"
        Dim matches = Regex.Matches(certificates, pattern)

        For Each m As Match In matches
            Dim certBytes As Byte() = System.Text.Encoding.ASCII.GetBytes(m.Value)
            collection.Add(New X509Certificate2(certBytes))
        Next

        If collection.Count = 0 Then
            MsgBox("The lets encrypt server sent back something that don't seem to be certificates but looks like ones.... eeeeeek", vbCritical)
            Exit Sub
        End If
        Dim p12withkey As X509Certificate2 = collection(0).CopyWithPrivateKey(privkey)
        Dim exportCollection As New X509Certificate2Collection()
        exportCollection.Add(p12withkey)
        For i As Integer = 1 To collection.Count - 1
            exportCollection.Add(collection(i))
        Next
        Dim p12Data As Byte() = exportCollection.Export(X509ContentType.Pkcs12, "")
        File.WriteAllBytes(savepath, p12Data)

    End Sub

End Class

