using System;
using System.Net.Sockets;
using System.Net;
using System.Windows.Forms;
using System.Text;
using System.Threading;
using System.Net.Security;

namespace Server_Chat_Message.Client
{
    public partial class ClientChat : Form1
    {
        private string uName = null;
        string textMess = null;
        IPAddress clientIP = IPAddress.Any;
        /*IPEndPoint serverEndPoint = adminLogin.serverEndPoint;*/
        Socket client;
        Thread conThr, thrDis;

        public ClientChat()
        {
            InitializeComponent();
        }

        private void WriteTextChatSafe(string text)
        {
            if (chatBox.InvokeRequired)
                chatBox.Invoke(new Action(delegate { WriteTextChatSafe(text); }));

            else
            {
                chatBox.Text += text;
            }
        }

        private void recvMess()
        {
            while (client.Connected)
            {
                // Receive data
                byte[] bytesRecv = new byte[512];
                int recvLen = client.Receive(bytesRecv);
                textMess = Encoding.ASCII.GetString(bytesRecv);
                WriteTextChatSafe(textMess);
            }
        }
        private void connectPort()
        {
            try
            {
                client = new Socket(clientIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                //MessageBox.Show("Connecting to server...");
                client.Connect(IPAddress.Parse("127.0.0.1"), 999);
                /*MessageBox.Show("Successfully connected!!!");*/

                // Receive message
                thrDis = new Thread(recvMess);
                thrDis.Start();
            }
            catch (Exception e)
            {
                MessageBox.Show("Failed to connect to server. Reason\n" + e);
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            
        }

        ~ClientChat() {
            // Close
            client.Shutdown(SocketShutdown.Both);
            client.Close();

            // Kill thread
            conThr.Abort();
            thrDis.Abort();
        }

        private void ClientChat_Load(object sender, EventArgs e)
        {
            conThr = new Thread(connectPort);
            /*conThr.IsBackground = true;*/
            conThr.Start();
        }
    }
}
