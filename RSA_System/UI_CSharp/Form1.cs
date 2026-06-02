using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Windows.Forms;

namespace UI_CSharp
{
    public partial class Form1 : Form
    {
        // =========================================================
        // PANELS
        // =========================================================

        private Panel pnlHeader;
        private Panel pnlStatus;

        // =========================================================
        // GROUPS
        // =========================================================

        private GroupBox grpKeyManagement;
        private GroupBox grpDigitalSignature;
        private GroupBox grpFileAuthentication;

        // =========================================================
        // LABELS
        // =========================================================

        private Label lblTitle;
        private Label lblSubtitle;
        private Label lblStatusText;

        private Label lblModuleSelect;
        private Label lblKeySize;

        private Label lblSigInput;
        private Label lblHashResult;
        private Label lblSigResult;

        // =========================================================
        // COMBOBOX
        // =========================================================

        private ComboBox cbModuleSelect;
        private ComboBox cbKeySize;

        // =========================================================
        // TEXTBOX
        // =========================================================

        private TextBox txtPublicKey;
        private TextBox txtPrivateKey;

        private TextBox txtSigInput;
        private TextBox txtHashOutput;
        private TextBox txtSignature;

        private TextBox txtFilePath;

        // =========================================================
        // BUTTONS
        // =========================================================

        private Button btnGenKey;
        private Button btnExportPublic;
        private Button btnExportPrivate;
        private Button btnImportKey;

        private Button btnSign;
        private Button btnVerify;

        private Button btnChooseFile;
        private Button btnSignFile;
        private Button btnVerifyFile;

        // =========================================================
        // RSA SERVICE
        // =========================================================

        private readonly RSAService _rsaService =
            new RSAService();

        // =========================================================
        // COLORS
        // =========================================================

        private readonly Color CrimsonDark =
            Color.FromArgb(18, 18, 20);

        private readonly Color CardBackground =
            Color.FromArgb(28, 28, 30);

        private readonly Color ControlInputBg =
            Color.FromArgb(44, 44, 46);

        private readonly Color TextPrimary =
            Color.White;

        private readonly Color TextSecondary =
            Color.FromArgb(142, 142, 147);

        private readonly Color BrandBlue =
            Color.FromArgb(0, 122, 255);

        private readonly Color BrandGreen =
            Color.FromArgb(52, 199, 89);

        private readonly Color BrandRed =
            Color.FromArgb(255, 59, 48);

        private readonly Color BrandOrange =
            Color.FromArgb(255, 149, 0);

        private readonly Color BrandPurple =
            Color.FromArgb(175, 82, 222);

        // =========================================================
        // FONTS
        // =========================================================

        private readonly Font FontTitle =
            new Font("Segoe UI", 16F, FontStyle.Bold);

        private readonly Font FontHeader =
            new Font("Segoe UI", 11F, FontStyle.Bold);

        private readonly Font FontRegular =
            new Font("Segoe UI", 10F, FontStyle.Regular);

        private readonly Font FontSmall =
            new Font("Segoe UI", 9F, FontStyle.Regular);

        // =========================================================
        // CONSTRUCTOR
        // =========================================================

        public Form1()
        {
            InitializeComponent();

            SetupCustomUI();
        }

        // =========================================================
        // UI SETUP
        // =========================================================

        private void SetupCustomUI()
        {
            this.Text =
                "RSA Digital Signature System";

            this.Size =
                new Size(1820, 850);

            this.MinimumSize =
                new Size(1820, 850);

            this.BackColor =
                CrimsonDark;

            this.StartPosition =
                FormStartPosition.CenterScreen;

            // =====================================================
            // HEADER
            // =====================================================

            pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 85,
                BackColor = Color.FromArgb(25, 25, 27)
            };

            lblTitle = new Label
            {
                Text = "RSA DIGITAL SIGNATURE",
                Font = FontTitle,
                ForeColor = BrandBlue,
                Location = new Point(30, 15),
                AutoSize = true
            };

            lblSubtitle = new Label
            {
                Text =
                "RSA Digital Signature & File Authentication System",

                Font = FontSmall,
                ForeColor = TextSecondary,
                Location = new Point(31, 48),
                AutoSize = true
            };

            pnlHeader.Controls.Add(lblTitle);
            pnlHeader.Controls.Add(lblSubtitle);

            this.Controls.Add(pnlHeader);

            // =====================================================
            // STATUS
            // =====================================================

            pnlStatus = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 35,
                BackColor = Color.FromArgb(25, 25, 27)
            };

            lblStatusText = new Label
            {
                Text = "● Hệ thống sẵn sàng",
                Font = FontSmall,
                ForeColor = TextSecondary,
                Location = new Point(20, 8),
                AutoSize = true
            };

            pnlStatus.Controls.Add(lblStatusText);

            this.Controls.Add(pnlStatus);

            // =====================================================
            // TAB 1 - KEY MANAGEMENT
            // =====================================================

            grpKeyManagement =
                CreateModernGroupBox(
                    "1. KEY MANAGEMENT",
                    20,
                    110,
                    560,
                    650);

            lblModuleSelect = new Label
            {
                Text = "Core xử lý:",
                Location = new Point(25, 40),
                ForeColor = TextSecondary,
                AutoSize = true
            };

            cbModuleSelect = new ComboBox
            {
                Location = new Point(180, 36),
                Width = 330,
                DropDownStyle =
                    ComboBoxStyle.DropDownList,
                BackColor = ControlInputBg,
                ForeColor = TextPrimary,
                FlatStyle = FlatStyle.Flat,
                Font = FontRegular
            };

            cbModuleSelect.Items.AddRange(
                new object[]
                {
                    "C# (.NET Native)",
                    "C++ (Custom Core)"
                });

            cbModuleSelect.SelectedIndex = 0;

            cbModuleSelect.SelectedIndexChanged +=
                CbModuleSelect_SelectedIndexChanged;

            lblKeySize = new Label
            {
                Text = "Độ dài khóa:",
                Location = new Point(25, 90),
                ForeColor = TextSecondary,
                AutoSize = true
            };

            cbKeySize = new ComboBox
            {
                Location = new Point(180, 86),
                Width = 330,
                DropDownStyle =
                    ComboBoxStyle.DropDownList,
                BackColor = ControlInputBg,
                ForeColor = TextPrimary,
                FlatStyle = FlatStyle.Flat,
                Font = FontRegular
            };

            cbKeySize.Items.AddRange(
                new object[]
                {
                    "1024 bits",
                    "2048 bits",
                    "4096 bits"
                });

            cbKeySize.SelectedIndex = 1;

            btnGenKey = CreateModernButton(
                "Generate RSA Keys",
                25,
                140,
                485,
                45,
                BrandBlue);

            btnGenKey.Click += BtnGenKey_Click;

            btnExportPublic = CreateModernButton(
                "Export Public Key",
                25,
                205,
                230,
                40,
                BrandGreen);

            btnExportPrivate = CreateModernButton(
                "Export Private Key",
                280,
                205,
                230,
                40,
                BrandOrange);

            btnImportKey = CreateModernButton(
                "Import Key",
                25,
                260,
                485,
                40,
                BrandPurple);

            btnExportPublic.Click +=
                BtnExportPublic_Click;

            btnExportPrivate.Click +=
                BtnExportPrivate_Click;

            btnImportKey.Click +=
                BtnImportKey_Click;

            txtPublicKey = CreateModernTextBox(
                25,
                330,
                485,
                120,
                "Public Key XML...");

            txtPrivateKey = CreateModernTextBox(
                25,
                480,
                485,
                120,
                "Private Key XML...");

            grpKeyManagement.Controls.AddRange(
                new Control[]
                {
                    lblModuleSelect,
                    cbModuleSelect,
                    lblKeySize,
                    cbKeySize,
                    btnGenKey,
                    btnExportPublic,
                    btnExportPrivate,
                    btnImportKey,
                    txtPublicKey,
                    txtPrivateKey
                });

            // =====================================================
            // TAB 2 - DIGITAL SIGNATURE
            // =====================================================

            grpDigitalSignature =
                CreateModernGroupBox(
                    "2. DIGITAL SIGNATURE",
                    620,
                    110,
                    560,
                    650);

            lblSigInput = new Label
            {
                Text = "Input Document:",
                Location = new Point(25, 40),
                ForeColor = TextSecondary,
                AutoSize = true
            };

            txtSigInput = CreateModernTextBox(
                25,
                65,
                485,
                180,
                "Nhập nội dung văn bản...");

            btnSign = CreateModernButton(
                "Create Signature",
                25,
                270,
                230,
                45,
                BrandOrange);

            btnVerify = CreateModernButton(
                "Verify Signature",
                280,
                270,
                230,
                45,
                BrandPurple);

            btnSign.Click += BtnSign_Click;
            btnVerify.Click += BtnVerify_Click;

            lblHashResult = new Label
            {
                Text = "SHA-256 Hash:",
                Location = new Point(25, 345),
                ForeColor = TextSecondary,
                AutoSize = true
            };

            txtHashOutput = CreateModernTextBox(
                25,
                370,
                485,
                60,
                "SHA256 Hash...");

            txtHashOutput.ReadOnly = true;

            lblSigResult = new Label
            {
                Text = "Digital Signature:",
                Location = new Point(25, 455),
                ForeColor = TextSecondary,
                AutoSize = true
            };

            txtSignature = CreateModernTextBox(
                25,
                480,
                485,
                120,
                "RSA Signature...");

            grpDigitalSignature.Controls.AddRange(
                new Control[]
                {
                    lblSigInput,
                    txtSigInput,
                    btnSign,
                    btnVerify,
                    lblHashResult,
                    txtHashOutput,
                    lblSigResult,
                    txtSignature
                });

            // =====================================================
            // TAB 3 - FILE AUTHENTICATION
            // =====================================================

            grpFileAuthentication =
                CreateModernGroupBox(
                    "3. FILE AUTHENTICATION",
                    1220,
                    110,
                    560,
                    650);

            Label lblFile = new Label
            {
                Text = "Đường dẫn file:",
                Location = new Point(25, 40),
                ForeColor = TextSecondary,
                AutoSize = true
            };

            txtFilePath = CreateModernTextBox(
                25,
                70,
                485,
                40,
                "Chọn file tài liệu...");

            btnChooseFile = CreateModernButton(
                "Browse File",
                25,
                140,
                485,
                45,
                BrandBlue);

            btnSignFile = CreateModernButton(
                "Sign File",
                25,
                220,
                230,
                45,
                BrandOrange);

            btnVerifyFile = CreateModernButton(
                "Verify File",
                280,
                220,
                230,
                45,
                BrandPurple);

            btnChooseFile.Click +=
                BtnChooseFile_Click;

            btnSignFile.Click +=
                BtnSignFile_Click;

            btnVerifyFile.Click +=
                BtnVerifyFile_Click;

            grpFileAuthentication.Controls.AddRange(
                new Control[]
                {
                    lblFile,
                    txtFilePath,
                    btnChooseFile,
                    btnSignFile,
                    btnVerifyFile
                });

            // =====================================================
            // ADD CONTROLS
            // =====================================================

            this.Controls.Add(grpKeyManagement);
            this.Controls.Add(grpDigitalSignature);
            this.Controls.Add(grpFileAuthentication);
        }

        // =========================================================
        // MODULE CHANGE
        // =========================================================

        // =========================================================
        // MODULE CHANGE
        // =========================================================

        private void CbModuleSelect_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Ánh xạ từ text hiển thị trên UI sang giá trị định danh xử lý của Service
            if (cbModuleSelect.SelectedItem.ToString() == "C++ (Custom Core)")
            {
                _rsaService.SelectedModule = "OpenSSL";
            }
            else
            {
                _rsaService.SelectedModule = "CSharp";
            }

            // Xóa trắng các ô chứa key cũ để tránh nhầm lẫn giữa 2 core xử lý
            txtPublicKey.Clear();
            txtPrivateKey.Clear();
            _rsaService.XmlPublicKey = null;
            _rsaService.XmlPrivateKey = null;

            UpdateStatus($"● Đã chuyển sang Engine: {_rsaService.SelectedModule}", BrandOrange);
        }

        // =========================================================
        // GENERATE KEY
        // =========================================================

        private void BtnGenKey_Click(
            object sender,
            EventArgs e)
        {
            try
            {
                int keySize =
                    cbKeySize.SelectedIndex == 0 ? 1024 :
                    cbKeySize.SelectedIndex == 2 ? 4096 :
                    2048;

                _rsaService.GenerateKeyPair(
                    keySize);

                txtPublicKey.Text =
                    _rsaService.XmlPublicKey;

                txtPrivateKey.Text =
                    _rsaService.XmlPrivateKey;

                UpdateStatus(
                    "● Generate RSA Keys SUCCESS",
                    BrandGreen);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        // =========================================================
        // EXPORT PUBLIC KEY
        // =========================================================

        private void BtnExportPublic_Click(
            object sender,
            EventArgs e)
        {
            SaveFileDialog sfd =
                new SaveFileDialog();

            sfd.Filter =
                "XML File|*.xml";

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                File.WriteAllText(
                    sfd.FileName,
                    txtPublicKey.Text);

                MessageBox.Show(
                    "Export Public Key SUCCESS");
            }
        }

        // =========================================================
        // EXPORT PRIVATE KEY
        // =========================================================

        private void BtnExportPrivate_Click(
            object sender,
            EventArgs e)
        {
            SaveFileDialog sfd =
                new SaveFileDialog();

            sfd.Filter =
                "XML File|*.xml";

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                File.WriteAllText(
                    sfd.FileName,
                    txtPrivateKey.Text);

                MessageBox.Show(
                    "Export Private Key SUCCESS");
            }
        }

        // =========================================================
        // IMPORT KEY
        // =========================================================

        private void BtnImportKey_Click(
            object sender,
            EventArgs e)
        {
            OpenFileDialog ofd =
                new OpenFileDialog();

            ofd.Filter =
                "XML File|*.xml";

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                string xml =
                    File.ReadAllText(ofd.FileName);

                if (xml.Contains("<D>"))
                {
                    txtPrivateKey.Text = xml;

                    _rsaService.XmlPrivateKey =
                        xml;
                }
                else
                {
                    txtPublicKey.Text = xml;

                    _rsaService.XmlPublicKey =
                        xml;
                }

                MessageBox.Show(
                    "Import Key SUCCESS");
            }
        }

        // =========================================================
        // SIGN
        // =========================================================

        private void BtnSign_Click(
            object sender,
            EventArgs e)
        {
            try
            {
                txtHashOutput.Text =
                    SHAService.ComputeSHA256(
                        txtSigInput.Text);

                txtSignature.Text =
                    _rsaService.SignData(
                        txtSigInput.Text);

                UpdateStatus(
                    "● Create Signature SUCCESS",
                    BrandGreen);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        // =========================================================
        // VERIFY
        // =========================================================

        private void BtnVerify_Click(
            object sender,
            EventArgs e)
        {
            try
            {
                bool valid =
                    _rsaService.VerifyData(
                        txtSigInput.Text,
                        txtSignature.Text);

                if (valid)
                {
                    MessageBox.Show(
                        "SIGNATURE VALID");

                    UpdateStatus(
                        "● Verify SUCCESS",
                        BrandGreen);
                }
                else
                {
                    MessageBox.Show(
                        "SIGNATURE INVALID");

                    UpdateStatus(
                        "● Verify FAILED",
                        BrandRed);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        // =========================================================
        // CHOOSE FILE
        // =========================================================

        private void BtnChooseFile_Click(
            object sender,
            EventArgs e)
        {
            OpenFileDialog ofd =
                new OpenFileDialog();

            if (ofd.ShowDialog() ==
                DialogResult.OK)
            {
                txtFilePath.Text =
                    ofd.FileName;
            }
        }

        // =========================================================
        // SIGN FILE
        // =========================================================

        private void BtnSignFile_Click(
            object sender,
            EventArgs e)
        {
            try
            {
                string signature =
                    _rsaService.SignFile(
                        txtFilePath.Text);

                File.WriteAllText(
                    txtFilePath.Text + ".sig",
                    signature);

                MessageBox.Show(
                    "FILE SIGNED SUCCESS");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        // =========================================================
        // VERIFY FILE
        // =========================================================

        private void BtnVerifyFile_Click(
            object sender,
            EventArgs e)
        {
            try
            {
                string sigPath =
                    txtFilePath.Text + ".sig";

                if (!File.Exists(sigPath))
                {
                    MessageBox.Show(
                        "Không tìm thấy file .sig");

                    return;
                }

                string signature =
                    File.ReadAllText(sigPath);

                bool valid =
                    _rsaService.VerifyFile(
                        txtFilePath.Text,
                        signature);

                if (valid)
                {
                    MessageBox.Show(
                        "FILE VALID");
                }
                else
                {
                    MessageBox.Show(
                        "FILE MODIFIED");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        // =========================================================
        // STATUS
        // =========================================================

        private void UpdateStatus(
            string message,
            Color color)
        {
            lblStatusText.Text =
                message;

            lblStatusText.ForeColor =
                color;

            this.Refresh();
        }

        // =========================================================
        // MODERN GROUPBOX
        // =========================================================

        private GroupBox CreateModernGroupBox(
            string title,
            int x,
            int y,
            int w,
            int h)
        {
            var gBox = new GroupBox
            {
                Text = title,
                Location = new Point(x, y),
                Size = new Size(w, h),
                ForeColor = BrandBlue,
                Font = FontHeader,
                BackColor = CardBackground,
                FlatStyle = FlatStyle.Flat
            };

            gBox.Paint += (s, e) =>
            {
                Graphics g =
                    e.Graphics;

                g.SmoothingMode =
                    SmoothingMode.AntiAlias;

                using (Pen p = new Pen(
                    Color.FromArgb(50, 50, 53), 1))
                {
                    g.DrawRectangle(
                        p,
                        0,
                        10,
                        gBox.Width - 1,
                        gBox.Height - 11);
                }

                TextRenderer.DrawText(
                    g,
                    gBox.Text,
                    gBox.Font,
                    new Point(12, 0),
                    gBox.ForeColor,
                    CardBackground);
            };

            return gBox;
        }

        // =========================================================
        // MODERN TEXTBOX
        // =========================================================

        private TextBox CreateModernTextBox(
            int x,
            int y,
            int w,
            int h,
            string placeholder)
        {
            var txt = new TextBox
            {
                Location = new Point(x, y),
                Width = w,
                Height = h,
                Multiline = h > 40,
                BackColor = ControlInputBg,
                ForeColor = TextPrimary,
                BorderStyle =
                    BorderStyle.FixedSingle,
                Font = FontRegular,
                PlaceholderText = placeholder
            };

            return txt;
        }

        // =========================================================
        // MODERN BUTTON
        // =========================================================

        private Button CreateModernButton(
            string text,
            int x,
            int y,
            int w,
            int h,
            Color baseColor)
        {
            var btn = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, h),
                ForeColor = Color.White,
                Font = FontHeader,
                BackColor = baseColor,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };

            btn.FlatAppearance.BorderSize = 0;

            btn.MouseEnter +=
                (s, e) =>
                btn.BackColor =
                    ControlPaint.Light(
                        baseColor,
                        0.15f);

            btn.MouseLeave +=
                (s, e) =>
                btn.BackColor =
                    baseColor;

            return btn;
        }

        private void Form1_Load(
            object sender,
            EventArgs e)
        {

        }
    }
}