using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Omni.Cryptography
{
    public static class NativeCertificateValidator
    {
        [UnmanagedCallersOnly(EntryPoint = "ValidateCertificate")]
        public static unsafe bool ValidateCertificate(byte* pfxPathPtr, byte* passwordPtr, byte* hostnamePtr, byte* outBuffer, int outBufferLen)
        {
            string details = string.Empty;

            try
            {
                string? pfxPath = Marshal.PtrToStringUTF8((IntPtr)pfxPathPtr);
                string? password = Marshal.PtrToStringUTF8((IntPtr)passwordPtr);
                string? expectedHostname = Marshal.PtrToStringUTF8((IntPtr)hostnamePtr);

                if (pfxPath == null || password == null || expectedHostname == null)
                    return false;

                using var certificate = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password);
                // 1. Validate expiration dates
                var now = DateTime.UtcNow;
                if (now < certificate.NotBefore || now > certificate.NotAfter)
                {
                    details = $"Certificate is expired or not yet valid. Valid from {certificate.NotBefore:u} to {certificate.NotAfter:u}.";
                    WriteStringToPtr(details, outBuffer, outBufferLen);
                    return false;
                }

                // 2. Validate hostname
                if (!IsHostnameMatch(certificate, expectedHostname))
                {
                    details = $"The hostname '{expectedHostname}' does not match the certificate.";
                    WriteStringToPtr(details, outBuffer, outBufferLen);
                    return false;
                }

                // 3. Validate trusted certificate authority (chain trust)
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                    if (!chain.Build(certificate))
                    {
                        var errors = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
                        details = $"The certificate is not trusted: {errors}";
                        WriteStringToPtr(details, outBuffer, outBufferLen);
                        return false;
                    }
                }

                details = "Certificate is valid, hostname matches, and issued by a trusted authority.";
                WriteStringToPtr(details, outBuffer, outBufferLen);
                return true;
            }
            catch (Exception ex)
            {
                details = $"Validation error: {ex.Message}";
                WriteStringToPtr(details, outBuffer, outBufferLen);
                return false;
            }
        }

        private static unsafe void WriteStringToPtr(string details, byte* buffer, int bufferLen)
        {
            if (bufferLen <= 0 || buffer == null)
                return;

            byte[] bytes = Encoding.UTF8.GetBytes(details);
            var len = Math.Min(bytes.Length, bufferLen - 1);
            Marshal.Copy(bytes, 0, (IntPtr)buffer, len);
            Marshal.WriteByte((IntPtr)buffer, len, 0); // null character \0
        }

        private static bool IsHostnameMatch(X509Certificate2 certificate, string hostname)
        {
            // Check Subject Alternative Name (SAN) extension
            foreach (var extension in certificate.Extensions)
            {
                if (extension.Oid?.Value == "2.5.29.17") // SAN
                {
                    var san = extension.Format(false);
                    var dnsNames = san.Split([','], StringSplitOptions.RemoveEmptyEntries)
                                      .Select(x => x.Trim().Replace("DNS Name=", "", StringComparison.OrdinalIgnoreCase));

                    if (dnsNames.Any(dns =>
                        dns.Equals(hostname, StringComparison.OrdinalIgnoreCase) ||
                        (dns.StartsWith("*.") && hostname.EndsWith(dns[1..], StringComparison.OrdinalIgnoreCase))))
                    {
                        return true;
                    }
                }
            }

            var subject = certificate.Subject;
            var cn = subject.Split(',')
                            .Select(p => p.Trim())
                            .FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));

            if (cn != null)
            {
                var value = cn.Substring(3);
                if (value.Equals(hostname, StringComparison.OrdinalIgnoreCase) ||
                    (value.StartsWith("*.") && hostname.EndsWith(value[1..], StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            return false;
        }
    }
}