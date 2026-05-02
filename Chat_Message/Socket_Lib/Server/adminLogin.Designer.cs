namespace Server_Chat_Message
{
    partial class adminLogin
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.sendBtn = new System.Windows.Forms.Button();
            this.chatDisplay = new System.Windows.Forms.RichTextBox();
            this.chatBox = new System.Windows.Forms.RichTextBox();
            this.userList = new System.Windows.Forms.ListBox();
            this.SuspendLayout();
            // 
            // sendBtn
            // 
            this.sendBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.sendBtn.Location = new System.Drawing.Point(524, 262);
            this.sendBtn.Name = "sendBtn";
            this.sendBtn.Size = new System.Drawing.Size(132, 45);
            this.sendBtn.TabIndex = 0;
            this.sendBtn.Text = "Send";
            this.sendBtn.UseVisualStyleBackColor = true;
            this.sendBtn.Click += new System.EventHandler(this.sendBtn_Click);
            // 
            // chatDisplay
            // 
            this.chatDisplay.Location = new System.Drawing.Point(-7, 2);
            this.chatDisplay.Name = "chatDisplay";
            this.chatDisplay.ReadOnly = true;
            this.chatDisplay.Size = new System.Drawing.Size(525, 254);
            this.chatDisplay.TabIndex = 1;
            this.chatDisplay.Text = "";
            // 
            // chatBox
            // 
            this.chatBox.Location = new System.Drawing.Point(2, 262);
            this.chatBox.Name = "chatBox";
            this.chatBox.Size = new System.Drawing.Size(516, 45);
            this.chatBox.TabIndex = 2;
            this.chatBox.Text = "";
            // 
            // userList
            // 
            this.userList.FormattingEnabled = true;
            this.userList.ItemHeight = 16;
            this.userList.Location = new System.Drawing.Point(524, 2);
            this.userList.Name = "userList";
            this.userList.Size = new System.Drawing.Size(132, 260);
            this.userList.TabIndex = 3;
            // 
            // adminLogin
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(658, 313);
            this.Controls.Add(this.userList);
            this.Controls.Add(this.chatBox);
            this.Controls.Add(this.chatDisplay);
            this.Controls.Add(this.sendBtn);
            this.Name = "adminLogin";
            this.Text = "adminLogin";
            this.Load += new System.EventHandler(this.adminLogin_Load);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button sendBtn;
        private System.Windows.Forms.RichTextBox chatDisplay;
        private System.Windows.Forms.RichTextBox chatBox;
        private System.Windows.Forms.ListBox userList;
    }
}