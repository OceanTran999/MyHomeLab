using Server_Chat_Message.Client;
using System;
using System.Threading;
using System.Windows.Forms;

namespace Server_Chat_Message
{
    public partial class Form1 : Form
    {
        // Constructor
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            ClientChat clientUI = new ClientChat();
            clientUI.Show();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            adminLogin adminUI = new adminLogin();
            adminUI.Show();
            button2.Enabled = false;
            button1.Enabled = true;
        }
    }
}
