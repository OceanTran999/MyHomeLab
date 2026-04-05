using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Web_Content
{
    public partial class Form1 : Form
    {
        string targetURL;

        public Form1()
        {
            InitializeComponent();
            InitializeAsync();
        }
        private string getMainDomain(string url, int index)
        {
            string retURL = "";

            while (url[index] != '/')
            {
                retURL += url[index];
                index++;
            }

            retURL += '/';
            return retURL;
        }
        private async void InitializeAsync()
        {
            await web_display.EnsureCoreWebView2Async();
        }
        private async void httpRequest(string text)
        {
            HttpClient client = new HttpClient();

            using (var resp = await client.GetAsync(text))
            {

                long? totalBytes = resp.Content.Headers.ContentLength;
                MessageBox.Show(totalBytes.ToString());

/*                int totalByteRead = 0;
                int byteRead;*/
                byte[] buffer = new byte[8192];

                string respMess = await resp.Content.ReadAsStringAsync();
                /*MessageBox.Show(respMess.Length.ToString());
                MessageBox.Show(resp.Headers.ToString().Length.ToString());*/

                web_display.NavigateToString(respMess.ToString());
            }
        }
        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                // Check if input is empty
                if (inputBox.Text == "")
                    throw new Exception("Input is empty...");

                if (inputBox.Text.StartsWith("http://"))
                    targetURL = "http://" + getMainDomain(inputBox.Text, 7);
                else if (inputBox.Text.StartsWith("https://"))
                    targetURL = "https://" + getMainDomain(inputBox.Text, 8);

                /*MessageBox.Show(targetURL);*/

                httpRequest(inputBox.Text);
                //outputBox.Text = respMess.ToString();

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            /*inputBox.Focus();*/
        }

        private void web_display_NavigationStarting(object sender, CoreWebView2NavigationStartingEventArgs e)
        {
            // Due to some <a> tag with "href" attribute does not include the full URL that leads to error when requesting, so I will make it back to homepage
            if (e.Uri.Contains("about:blank"))
            {
                MessageBox.Show("Error requesting to URL. Back to homepage...");
                httpRequest(targetURL);
            }
            // Update URL in textbox
            inputBox.Text = targetURL;
        }
}
}