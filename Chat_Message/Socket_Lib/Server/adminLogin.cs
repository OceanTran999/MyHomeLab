using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Server_Chat_Message
{
    public partial class adminLogin : Form
    {
        private static IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 999);
        private Socket listener, acpt;
        private Thread thrLis, recvThr, sendThr, resendThr, handleRequest, thrFirstMess;
        string recvData = "", readMess = "";

        public adminLogin()
        {
            InitializeComponent();
        }

        private void ReadTextChatSafe(Control ctrl, string textRead)
        {
            if (chatDisplay.InvokeRequired)
                chatDisplay.Invoke(new Action(delegate { ReadTextChatSafe(ctrl, textRead); }));

            else
                textRead = ctrl.Text;
        }

        private void WriteTextChatSafe(Control ctrl, string text)
        {
            if (ctrl.InvokeRequired)
                ctrl.Invoke(new Action(delegate { WriteTextChatSafe(ctrl, text); })) ;

            else
            {
                if(ctrl is RichTextBox)
                    ctrl.Text += text;
                else if(ctrl is TextBox)
                    ctrl.Text = text;
            }
        }

        private void recvAndResend()
        {
            try
            {
                // Receive data from a user
                byte[] bytes = new byte[250];
                int recvLen = acpt.Receive(bytes);
                recvData += Encoding.ASCII.GetString(bytes);
                WriteTextChatSafe(chatDisplay, recvData);

                // Resend received data to other user
                resendThr = new Thread(() =>
                {
                    byte[] byteRes = Encoding.UTF8.GetBytes(recvData);
                    int reSend = acpt.Send(byteRes);
                });
                resendThr.Start();
            }
            catch (Exception e)
            {
                MessageBox.Show($"Error: {e}");
            }
        }

        private void send()
        {
            readMess = chatBox.Text;
            /*ReadTextChatSafe(chatBox, readMess);*/
            /*MessageBox.Show(readMess);*/
            if (readMess == "")
                MessageBox.Show("Please type a message!!!");
            else
            {
                byte[] message = Encoding.UTF8.GetBytes(readMess);
                int sendData = acpt.Send(message);
            }
        }

        private void openPort()
        {
            try
            {
                listener = new Socket(serverEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(serverEndPoint);
                listener.Listen(10);
                MessageBox.Show("Listening in " + serverEndPoint.Address + ":" + serverEndPoint.Port + "...");  // Debug

                // Create a Thread to handle each clients request
                handleRequest = new Thread(() =>
                {
                    // Set a loop so that can reaccept with new requests
                    while (true)
                    {
                        acpt = listener.Accept();
                        // Notify fist message
                        thrFirstMess = new Thread(() =>
                        {
                            string message = "A user has joined the chat\n";
                            byte[] messData = Encoding.ASCII.GetBytes(message);
                            acpt.Send(messData);
                            WriteTextChatSafe(chatDisplay, message);
                        });
                        thrFirstMess.Start();

                        // Thread for receiving and resending data to other users
                        recvThr = new Thread(recvAndResend);
                        recvThr.Start();
                    }
                });
                handleRequest.Start();
            }
            catch (Exception e)
            {
                MessageBox.Show("Failed to open server chat. Reason:...\n" + e);
            }

        }

        private void sendBtn_Click(object sender, EventArgs e)
        {
            /*sendThr = new Thread(send);
            sendThr.Start();
            WriteTextChatSafe(chatBox, "");*/
            send();
            chatDisplay.Text += $"You: {readMess}\n";
            chatBox.Text = String.Empty;
        }

        private void adminLogin_Load(object sender, EventArgs e)
        {
            thrLis = new Thread(openPort);
            thrLis.Start();
        }

        ~adminLogin()
        {
            // Close server
            listener.Shutdown(SocketShutdown.Both);
            listener.Close();

            acpt.Shutdown(SocketShutdown.Both);
            acpt.Close();

            // Terminate thread
            thrLis.Abort();
            recvThr.Abort();
            sendThr.Abort();
            resendThr.Abort();
            handleRequest.Abort();
            thrFirstMess.Abort();
        }
    }
}
