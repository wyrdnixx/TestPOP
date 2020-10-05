
using OpenPop.Common.Logging;
using OpenPop.Mime;
using OpenPop.Pop3;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;

// http://hpop.sourceforge.net/examples.php


namespace TestPOP
{
    class Program
    { // Generate an unqiue email file name based on date time

        private static List<MailAccount> MailAccounts = new List<MailAccount>();
        private static String PubKey = null;
        private static String PrivKey = null;

        private static X509Certificate2 localCert = null;

        /// <summary>
        /// Defines a logger for managing system logging output  
        /// </summary>
        public interface ILog
        {
            /// <summary>
            /// Logs an error message to the logs
            /// </summary>
            /// <param name="message">This is the error message to log</param>
            void LogError(string message);

            /// <summary>
            /// Logs a debug message to the logs
            /// </summary>
            /// <param name="message">This is the debug message to log</param>
            void LogDebug(string message);
        }

        static void Main(string[] args)
        {
            ChangeLogging();


        

            if (args.Length == 0)
            {
                getConfig();
                startProcessing();
            } else if(args.Length == 3)
            {
                getConfig();
                writetoconfig(args);
            } else
            {
                DefaultLogger.Log.LogError("Error: Programm started with invalid parameter lengt. \n Use '...exe <mailboxname> <Email@address.com> <cleartextpassword>");

            }

            


        

        }

        private static void writetoconfig(string[] args) {

            String pwdenc = Encryption(args[2]);
            DefaultLogger.Log.LogDebug("Encrypted-PWD: " + pwdenc);
            DefaultLogger.Log.LogDebug( System.Environment.NewLine +
                @"<Account>" + System.Environment.NewLine +
                @"<UserName>" + args[0] + @"</UserName>" + System.Environment.NewLine +
                @"<Mail>" + args[1] + @"</Mail>" + System.Environment.NewLine +
                @"<Password>" + pwdenc + @"</Password>" + System.Environment.NewLine +
                @"</Account>"); 

        }

        private static void startProcessing()
        {
            foreach (MailAccount acc in MailAccounts)
            {
                DefaultLogger.Log.LogDebug("------------ From Accounts-List: " + acc.Username);
                proccessMailAccount(acc);
            }
        }

        static void getConfig()
        {
           
            XDocument xmlDoc = XDocument.Load(".\\config.xml");


            IEnumerable<XElement> CfgCerts = xmlDoc.Descendants("SecureCertificate");
            if (CfgCerts.Count() !=1 )
            {
                DefaultLogger.Log.LogError("CFG-Error: More than one certificate specified.");
            }else
            {

                foreach (var cer in xmlDoc.Descendants("SecureCertificate"))
                {                    
                    DefaultLogger.Log.LogDebug("CertSN from Config: " + cer.Value);
                    getLocalCertificate(cer.Value);
                }
            }
            

                foreach (var acc in xmlDoc.Descendants("Account"))
            {
                try
                {
                    DefaultLogger.Log.LogDebug("Config : Add Name to Config : " + acc.Element("UserName").Value);
                    DefaultLogger.Log.LogDebug("Config : Add Mailbox to Config : " + acc.Element("Mail").Value);
                    DefaultLogger.Log.LogDebug("Config : Add (encrypted) Password to Config : " + acc.Element("Password").Value);

                    MailAccounts.Add(new MailAccount(acc.Element("UserName").Value, acc.Element("Mail").Value, acc.Element("Password").Value));

                } catch (Exception e)
                {
                    DefaultLogger.Log.LogError("ERR while Reading XML Document value: " + acc.Element("UserName").Value + " -> " + e.Message);
                }
            };

        }

        private static void getLocalCertificate(String certThumbPrint)
        {
            X509Store store = new X509Store("My", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certCollection = store.Certificates.Find(
            X509FindType.FindByThumbprint, certThumbPrint, false);
            store.Close();

            if (1 != certCollection.Count)
            {
                DefaultLogger.Log.LogError("Error: No certificate or more than one found containing thumbprint ");
            } else
            {
                PrivKey =  certCollection[0].GetRSAPrivateKey().ToString();
                PubKey =  certCollection[0].GetRSAPublicKey().ToString();
                //DefaultLogger.Log.LogDebug("PrivKey= " + PrivKey);
                //DefaultLogger.Log.LogDebug("PrivKey= " + PubKey);
                localCert = certCollection[0];

                // TESTS
                String pwdenc = Encryption("mwolf");
                DefaultLogger.Log.LogDebug("PWD-Encrypted: " + pwdenc);
                String pwddec = Decryption(pwdenc);
                DefaultLogger.Log.LogDebug("PWD-Decrypted: " + pwddec);

            }

        }

        static void proccessMailAccount(MailAccount _mailAccount)
        {
            List<Message> AllMessages = FetchAllMessages("192.168.1.214", 995, true, _mailAccount.Username, Decryption(_mailAccount.Password));
            
        }

        static void oldMain()
        {

            String pwdenc = Encryption("mwolf");

            DefaultLogger.Log.LogDebug("PWD-Encrypted: " + pwdenc);

            //string[] lines = { "mwolf", theSecureString.ToString(), };
            //System.IO.File.WriteAllLines(@".\pass.txt", lines);

            String pwddec = Decryption(pwdenc);
            DefaultLogger.Log.LogDebug("PWD-Decrypted: " + pwddec);



            //List<Message> AllMessages = FetchAllMessages("192.168.1.214", 995, true, "mwolf@chaos.local", "1mwolf");
            List<Message> AllMessages = FetchAllMessages("192.168.1.214", 995, true, "mwolf@chaos.local", pwddec);

            Console.WriteLine("Mail-Info:");

            if (AllMessages != null)
            {
                foreach (Message m in AllMessages)
                {
                    Console.WriteLine(m.Headers.From);

                    // FileInfo about the location to save/load message
                    String filename = "mail_" + m.Headers.MessageId + ".eml";

                    FileInfo file = new FileInfo(filename);

                    // Save the full message to some file
                    m.Save(file);

                }
            }
        }


        /// <summary>
        /// Example showing:
        ///  - how to fetch all messages from a POP3 server
        /// </summary>
        /// <param name="hostname">Hostname of the server. For example: pop3.live.com</param>
        /// <param name="port">Host port to connect to. Normally: 110 for plain POP3, 995 for SSL POP3</param>
        /// <param name="useSsl">Whether or not to use SSL to connect to server</param>
        /// <param name="username">Username of the user on the server</param>
        /// <param name="password">Password of the user on the server</param>
        /// <returns>All Messages on the POP3 server</returns>
        public static List<Message> FetchAllMessages(string hostname, int port, bool useSsl, string username, string password)
        {

            bool ConOk = false;
            bool AuthOk = false;

            // The client disconnects from the server when being disposed
            using (Pop3Client client = new Pop3Client())
            {
                // Connect to the server
                
                client.Connect(hostname, port, useSsl,500,500, certificateValidator);

                ConOk = true;
                
                try
                {

                    // Authenticate ourselves towards the server
                    client.Authenticate(username, password);
                    AuthOk = true;

                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR : " + username + " : Auth not successfull", e.Message);
                    
                }

                if(ConOk & AuthOk)
                { 
                    // Get the number of messages in the inbox
                    int messageCount = client.GetMessageCount();

                    // We want to download all messages
                    List<Message> allMessages = new List<Message>(messageCount);

                    // Messages are numbered in the interval: [1, messageCount]
                    // Ergo: message numbers are 1-based.
                    // Most servers give the latest message the highest number
                    for (int i = messageCount; i > 0; i--)
                    {
                        //   allMessages.Add(client.GetMessage(i));
                        Message m = client.GetMessage(i);

                        String filename = "mail_" + m.Headers.MessageId + ".eml";

                        FileInfo file = new FileInfo(filename);
                        // Save the full message to some file
                        m.Save(file);

                        client.DeleteMessage(i);



                    }
                    // Now return the fetched messages
                    return allMessages;
                } else
                {
                    DefaultLogger.Log.LogError("ERROR : " + username + "No connection or not authenticated...");


                    
                    //Console.WriteLine("ERROR: no connection or not authenticated...");
                    return null;
                }

                

                
            }
        }

        private static bool certificateValidator(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            // We should check if there are some SSLPolicyErrors, but here we simply say that
            // the certificate is okay - we trust it.
            return true;
        }

        public static void ChangeLogging()
        {
            // All logging is sent trough logger defined at DefaultLogger.Log
            // The logger can be changed by calling DefaultLogger.SetLog(someLogger)

            // By default all logging is sent to the System.Diagnostics.Trace facilities.
            // These are not very useful if you are not debugging
            // Instead, lets send logging to a file:
            ////DefaultLogger.SetLog(new FileLogger());
            ////FileLogger.LogFile = new FileInfo("MyLoggingFile.log");

            // It is also possible to implement your own logging:
            DefaultLogger.SetLog(new MyOwnLogger());
        }



        public static string Encryption(string strText)
        {
            //var publicKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            
            var testData = Encoding.UTF8.GetBytes(strText);

            using (RSA rsa =localCert.GetRSAPublicKey())
            {
                try
                {
                    // client encrypting data with public key issued by server                    
                    //rsa.FromXmlString(publicKey.ToString());
                    //var encryptedData = rsa.Encrypt(testData, true);
                    //var base64Encrypted = Convert.ToBase64String(encryptedData);
                    
                    var encryptedData = rsa.Encrypt(testData, RSAEncryptionPadding.OaepSHA256);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    
                    return base64Encrypted;
                }
                catch (Exception e)
                {
                    DefaultLogger.Log.LogError("Error on encrypting password: " + e.Message);
                    return null;
                }
            }
        }

        public static string Decryption(string strText)
        {
            //var privateKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent><P>/aULPE6jd5IkwtWXmReyMUhmI/nfwfkQSyl7tsg2PKdpcxk4mpPZUdEQhHQLvE84w2DhTyYkPHCtq/mMKE3MHw==</P><Q>3WV46X9Arg2l9cxb67KVlNVXyCqc/w+LWt/tbhLJvV2xCF/0rWKPsBJ9MC6cquaqNPxWWEav8RAVbmmGrJt51Q==</Q><DP>8TuZFgBMpBoQcGUoS2goB4st6aVq1FcG0hVgHhUI0GMAfYFNPmbDV3cY2IBt8Oj/uYJYhyhlaj5YTqmGTYbATQ==</DP><DQ>FIoVbZQgrAUYIHWVEYi/187zFd7eMct/Yi7kGBImJStMATrluDAspGkStCWe4zwDDmdam1XzfKnBUzz3AYxrAQ==</DQ><InverseQ>QPU3Tmt8nznSgYZ+5jUo9E0SfjiTu435ihANiHqqjasaUNvOHKumqzuBZ8NRtkUhS6dsOEb8A2ODvy7KswUxyA==</InverseQ><D>cgoRoAUpSVfHMdYXW9nA3dfX75dIamZnwPtFHq80ttagbIe4ToYYCcyUz5NElhiNQSESgS5uCgNWqWXt5PnPu4XmCXx6utco1UVH8HGLahzbAnSy6Cj3iUIQ7Gj+9gQ7PkC434HTtHazmxVgIR5l56ZjoQ8yGNCPZnsdYEmhJWk=</D></RSAKeyValue>";

            byte[] testData = Convert.FromBase64String(strText);
            //byte[] testData = Encoding.ASCII.GetBytes(strText);
            using (RSA rsa = localCert.GetRSAPrivateKey())
            {
                try
                {
                    byte[] decryptedData = rsa.Decrypt(testData, RSAEncryptionPadding.OaepSHA256);
                    System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                    return encoding.GetString(decryptedData);
                    
                }
                catch (Exception e)
                {
                    DefaultLogger.Log.LogError("Error on decrypting password: " + e.Message);
                    return null;
                }
            }
        }


    }


    class MyOwnLogger : ILog
    {


        string LogFilePath = System.Environment.CurrentDirectory + @"\Loggfile.Log";


        public void LogError(string message)
        {

           
            using (StreamWriter sw = File.AppendText(LogFilePath))
            {sw.WriteLine("ERROR-DEBUG: " + message);}

            Console.WriteLine("ERROR!!!: " + message);
            System.Diagnostics.Debug.WriteLine("ERROR-DEBUG: " + message);
        }

        public void LogDebug(string message)
        {

            
            using (StreamWriter sw = File.AppendText(LogFilePath))
            { sw.WriteLine("DEBUG-Line: " + message); }

            Console.WriteLine("DEBUG-Line: " + message);
            System.Diagnostics.Debug.WriteLine("DEBUG-Log: " + message);
            // Dont want to log debug messages
        }
    }


}