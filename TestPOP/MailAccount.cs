using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestPOP
{
    class MailAccount
    {

        public String Username;
        public String Mail;
        public String Password;

        public MailAccount (String _Username, String _Mail, String _Password)
        {
            this.Username = _Username;
            this.Mail = _Mail;
            this.Password = _Password;
        }

    }
}
