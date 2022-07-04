using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using SuperSimpleTcp;
using System.Security.Cryptography;
namespace ServerWPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

        }

        SimpleTcpServer server;

        static string ipClient;
        static byte[] AlicePublicKey;
        static byte[] AlicePrivateKey;
        static byte[] session_Key;
        static byte[] IV = new byte[16];
        static string Massag = null;
        static byte[] RegID_Key;
        static byte[] RegIV;
        static byte[] RegHash;
        static string nick;
        static int id11;
        static int flot;

        private void StartButt_Click(object sender, RoutedEventArgs e)
        {
            server = new SimpleTcpServer(IpBox.Text);
            server.Events.ClientConnected += Events_clientConnected;
            server.Events.ClientDisconnected += Event_clientDisconnected;
            server.Events.DataReceived += Event_DataReceived;


            server.Start();
            infoListbox.Items.Add("Connect...");
            StartButt.IsEnabled = false;
        }
        public void setid(int id1)
        {
            id11 = id1;
        }
        private void Event_DataReceived(object sender, DataReceivedEventArgs e)
        {
            var md5 = MD5.Create();
            Dispatcher.BeginInvoke(new Action(delegate
            {

                BdClass registrat = new BdClass();
                byte[] M_C = e.Data;
                unbyte_massiv(M_C, 2, out byte[] type_massage, out byte[] M_C1);
                int type_massage1 = Convert.ToInt16(Encoding.UTF8.GetString(type_massage));
                Message mess = new Message();

                int ost = mess.SetTypeM(type_massage1, M_C1);
                byte[] rep = mess.GetTypeM();
                if (rep != null)
                {
                    if (ost == 1)
                    {
                        server.Send(e.IpPort, rep);
                    }
                    else
                    {
                        System.Threading.Thread.Sleep(5000);
                        server.DisconnectClient(e.IpPort);
                    }

                }
                else
                {
                    int id = Convert.ToInt16(UTF8Encoding.UTF8.GetString(M_C1));
                    CryptographyClass keys = new CryptographyClass();
                    BdClass bd = new BdClass();

                    registrat.allnews(id, out List<byte[]> reqfre, out List<byte[]> message, out string reply1);
                    registrat.Check_SessKey(id, out byte[] iv, out string nickk, out byte[] seskey, out DateTime time);
                    registrat.Check_Login(nickk, out string reply, out byte[] IDKey, out byte[] IV, out byte[] Hash);

                    int countMess = message.Count;
                    byte[] mess1 = new byte[5];
                    byte[] mess2;
                    int ff = 0;

                    if(reply1=="11")
                    {
                        foreach (byte[] s in message)
                        {
                            int l = s.Length;
                            mess2 = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(l)), s);
                            if (ff == 0)
                            {
                                mess1 = mess2;
                                ff = 1;
                            }
                            else
                            {
                                mess1 = byte_massiv(mess1, mess2);
                            }
                            
                        }
                        byte[] le = Encoding.UTF8.GetBytes(Convert.ToString(countMess));
                        le = Encoding.UTF8.GetBytes(Convert.ToString(le.Length));
                        mess1 = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(countMess)), mess1);
                        mess1 = byte_massiv(le, mess1);
                        keys.EncryptMsg_IV(IDKey, mess1, out mess1, IV);
                        keys.EncryptMsg_IV(seskey, mess1, out mess1, iv);
                        server.Send(e.IpPort, byte_massiv(UTF8Encoding.UTF8.GetBytes("52"), mess1));


                        foreach (byte[] m in reqfre)
                        {
                            // шифрование и отправка запросов
                            keys.EncryptMsg_IV(IDKey, m, out byte[] encry, IV);
                            keys.EncryptMsg_IV(seskey, encry, out encry, iv);
                            server.Send(e.IpPort, byte_massiv(UTF8Encoding.UTF8.GetBytes("51"), encry));
                        }
                    }
                    if(reply1 =="10")
                    {
                        foreach (byte[] m in reqfre)
                        {
                            // шифрование и отправка запросов
                            keys.EncryptMsg_IV(IDKey, m, out byte[] encry, IV);
                            keys.EncryptMsg_IV(seskey, encry, out encry, iv);
                            server.Send(e.IpPort, byte_massiv(UTF8Encoding.UTF8.GetBytes("51"), encry));
                        }
                        
                    }
                    if(reply1=="01")
                    {
                        foreach (byte[] s in message)
                        {
                            int l = s.Length;
                            mess2 = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(l)), s);
                            if (ff == 0)
                            {
                                mess1 = mess2;
                                ff = 1;
                            }
                            else
                            {
                                mess1 = byte_massiv(mess1, mess2);
                            }

                        }
                        byte[] le = Encoding.UTF8.GetBytes(Convert.ToString(countMess));
                        le = Encoding.UTF8.GetBytes(Convert.ToString(le.Length));
                        mess1 = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(countMess)), mess1);
                        mess1 = byte_massiv(le, mess1);
                        keys.EncryptMsg_IV(IDKey, mess1, out mess1, IV);
                        keys.EncryptMsg_IV(seskey, mess1, out mess1, iv);
                        server.Send(e.IpPort, byte_massiv(UTF8Encoding.UTF8.GetBytes("52"), mess1));
                    }
                    if(reply1=="00")
                    {

                    }
                   
                    System.Threading.Thread.Sleep(5000);
                    server.DisconnectClient(e.IpPort);
                }



            }));
        }

        private void mix_byte(byte[] one, byte[] two, out byte[] mix)
        {
            mix = new byte[one.Length * 2];
            for (int i = 0; i < one.Length; i++)
            {
                int a = i + 1;
                System.Buffer.BlockCopy(one, i, mix, i, 1);
                System.Buffer.BlockCopy(two, i, mix, a, 1);
            }
        }
        private byte[] byte_massiv(byte[] one, byte[] two)
        {
            byte[] mass = new byte[one.Length + two.Length];

            System.Buffer.BlockCopy(one, 0, mass, 0, one.Length);
            System.Buffer.BlockCopy(two, 0, mass, one.Length, two.Length);
            return (mass);
        }
        private void unbyte_massiv(byte[] mass, out byte[] one, out byte[] two, out byte[] fre)
        {

            byte[] mass1 = new byte[mass.Length];
            one = new byte[16];
            two = new byte[2];
            fre = new byte[mass.Length - 18];
            System.Buffer.BlockCopy(mass, 0, one, 0, 16);
            System.Buffer.BlockCopy(mass, 16, two, 0, 2);
            System.Buffer.BlockCopy(mass, 18, fre, 0, mass.Length - 18);

        }
        private void unbyte_massiv(byte[] mass, int lenght, out byte[] one, out byte[] two)
        {

            byte[] mass1 = new byte[mass.Length];
            one = new byte[lenght];
            two = new byte[mass.Length - lenght];
            System.Buffer.BlockCopy(mass, 0, one, 0, lenght);
            System.Buffer.BlockCopy(mass, lenght, two, 0, mass.Length - lenght);


        }


        private void Event_clientDisconnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(delegate
            {
                infoListbox.Items.Add($"{e.IpPort} disconnected");
            }));
        }

        private void Events_clientConnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(delegate
            {
                infoListbox.Items.Add($"{e.IpPort} connected");
                ipClient += e.IpPort;
                CryptographyClass crypto = new CryptographyClass();
                //1.1


            }));
        }
        public class Message
        {
            private int X;
            private byte[] rep;
            static byte[] AlicePublicKey;
            static byte[] AlicePrivateKey;
            static byte[] AlicePublicKey_ID;
            static byte[] AlicePrivateKey_ID;
            static byte[] BobPublickKey_ID;
            static byte[] ID_Key;
            static byte[] ID_IV;
            static byte[] sessionKey;
            static byte[] sessionKey_IV;
            static byte[] login_byte;
            static byte[] hash_byte;
            static string login;

            private byte[] byte_massiv(byte[] one, byte[] two)
            {
                byte[] mass = new byte[one.Length + two.Length];

                System.Buffer.BlockCopy(one, 0, mass, 0, one.Length);
                System.Buffer.BlockCopy(two, 0, mass, one.Length, two.Length);
                return (mass);
            }
            private void unbyte_massiv_IV(byte[] ty, out byte[] IV1, out byte[] msg1)
            {
                byte[] msg = new byte[ty.Length - 16];
                byte[] IV = new byte[16];
                System.Buffer.BlockCopy(ty, 0, IV, 0, 16);
                System.Buffer.BlockCopy(ty, 16, msg, 0, ty.Length - 16);
                msg1 = msg;
                IV1 = IV;
            }
            private void unbyte_massiv(byte[] mass, out byte[] one, out byte[] two, out byte[] fre)
            {

                byte[] mass1 = new byte[mass.Length];
                one = new byte[16];
                two = new byte[2];
                fre = new byte[mass.Length - 18];
                System.Buffer.BlockCopy(mass, 0, one, 0, 16);
                System.Buffer.BlockCopy(mass, 16, two, 0, 2);
                System.Buffer.BlockCopy(mass, 18, fre, 0, mass.Length - 18);

            }
            private void unbyte_massiv(byte[] mass, int lenght, out byte[] one, out byte[] two)
            {

                byte[] mass1 = new byte[mass.Length];
                one = new byte[lenght];
                two = new byte[mass.Length - lenght];
                System.Buffer.BlockCopy(mass, 0, one, 0, lenght);
                System.Buffer.BlockCopy(mass, lenght, two, 0, mass.Length - lenght);


            }
            private void unbyte_massiv(byte[] mass, out byte[] one, out byte[] two)
            {

                byte[] mass1 = new byte[mass.Length];
                one = new byte[2];
                two = new byte[mass.Length - 2];

                System.Buffer.BlockCopy(mass, 0, one, 0, 2);
                System.Buffer.BlockCopy(mass, 2, two, 0, mass.Length - 2);


            }

            public int SetTypeM(int x, byte[] message)
            {
                int ost = 1;
                this.X = x;
                CryptographyClass crypto = new CryptographyClass();
                BdClass registrat = new BdClass();
                if (X == 11)
                {
                    crypto.generate_PublicKey(out AlicePublicKey, out AlicePrivateKey);
                    sessionKey = crypto.Creating_SessionKey(message, AlicePrivateKey);
                    this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(11)), AlicePublicKey);

                }
                if (X == 12)
                {
                    crypto.generate_PublicKey(out AlicePublicKey_ID, out AlicePrivateKey_ID);
                    BobPublickKey_ID = message;
                    ID_Key = crypto.Creating_SessionKey(BobPublickKey_ID, AlicePrivateKey_ID);
                    this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(12)), AlicePublicKey_ID);
                }
                if (X == 13)
                {

                    byte[] log_leght;
                    // Извлечение публичного сеансового ключа из массива
                    unbyte_massiv_IV(message, out sessionKey_IV, out message);
                    // расшифровка
                    crypto.DecryptMsg(sessionKey, message, sessionKey_IV, out message);
                    // извлечение публичнного ID_Key и длинны логина из массива
                    unbyte_massiv(message, out ID_IV, out log_leght, out message);
                    // расшифровка
                    crypto.DecryptMsg(ID_Key, message, ID_IV, out message);
                    // разделение логина и хэша
                    unbyte_massiv(message, Convert.ToInt32(Encoding.UTF8.GetString(log_leght)), out login_byte, out hash_byte);
                    login = Encoding.UTF8.GetString(login_byte);

                    // проверка логина на повтор в базе данных
                    registrat.Check_Login(login, hash_byte, ID_Key, ID_IV, out string reply1);
                    byte[] reply1_byte;
                    // шифровка результата проверки
                    crypto.EncryptMsg_IV(ID_Key, Encoding.UTF8.GetBytes(reply1), out reply1_byte, ID_IV);
                    crypto.EncryptMsg_IV(sessionKey, reply1_byte, out reply1_byte, sessionKey_IV);
                    this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(13)), reply1_byte);
                }
                if (X == 21)
                {
                    crypto.generate_PublicKey(out AlicePublicKey, out AlicePrivateKey);
                    sessionKey = crypto.Creating_SessionKey(message, AlicePrivateKey);
                    this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(21)), AlicePublicKey);
                }
                if (X == 22)
                {

                    unbyte_massiv_IV(message, out sessionKey_IV, out message);
                    crypto.DecryptMsg(sessionKey, message, sessionKey_IV, out message);
                    login = Encoding.UTF8.GetString(message);
                    //Проверка логина на его начилие в базе данных
                    registrat.Check_Login(Encoding.UTF8.GetString(message), out string replys, out ID_Key, out ID_IV, out hash_byte);
                    crypto.EncryptMsg_IV(sessionKey, Encoding.UTF8.GetBytes(replys), out rep, sessionKey_IV);
                    this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(22)), rep);
                }
                if (X == 23)
                {
                    var md5 = MD5.Create();
                    //расшифровка сообщения
                    crypto.DecryptMsg(sessionKey, message, sessionKey_IV, out message);
                    crypto.DecryptMsg(ID_Key, message, ID_IV, out message);

                    unbyte_massiv(message, 1, out byte[] sole, out byte[] HashMix);
                    //извлечение соли из массива
                    int time = sole[0];
                    var rand = new Random(time);
                    byte[] sole1 = new byte[hash_byte.Length];
                    // геенрация массива байтов с помощью соли
                    rand.NextBytes(sole1);
                    int result = 0;
                    //смешивание массива и хэша из базы данных
                    byte[] mix = byte_massiv(sole1, hash_byte);
                    //хэширование
                    byte[] Hash_Test = md5.ComputeHash(mix);
                    //сравынение с полученным хешэм
                    for (int i = 0; i < (HashMix.Length); i++)
                    {
                        if (Hash_Test[i] == HashMix[i])
                        {
                            result++;
                        }
                        else
                        {

                        }
                    }


                    if (result == (HashMix.Length))
                    {
                        //Сохранение даты на 5 часов вперед
                        DateTime localDate = DateTime.Now.AddHours(5);
                        //сохранение сеансового ключа и даты
                        registrat.Check_and_add_SessKey_log(login, sessionKey, localDate, sessionKey_IV, out int id);
                        //шифрование id сеансвого ключа клиента
                        crypto.EncryptMsg_IV(ID_Key, Encoding.UTF8.GetBytes(Convert.ToString(id)), out byte[] result1, ID_IV);
                        crypto.EncryptMsg_IV(sessionKey, result1, out result1, sessionKey_IV);

                        this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(23)), result1);


                    }
                    else
                    {
                        //шифрование отрицательного ответа
                        byte[] reply = Encoding.UTF8.GetBytes("Неправильный пароль!");
                        crypto.EncryptMsg_IV(ID_Key, reply, out reply, ID_IV);
                        crypto.EncryptMsg_IV(sessionKey, reply, out reply, sessionKey_IV);
                        this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(23)), reply);


                    }


                }
                if (X == 31)
                {
                    //извлекает длинну Id из полученного массива
                    unbyte_massiv(message, 1, out byte[] valueid, out message);
                    //извлекает Id 
                    unbyte_massiv(message, Convert.ToInt16(Encoding.UTF8.GetString(valueid)), out byte[] byteid, out message);

                    int id = Convert.ToInt16(Encoding.UTF8.GetString(byteid));
                    DateTime timeDech = DateTime.Now;
                    DateTime timeDech1 = DateTime.Now;
                    //вывод данных по Id сеансовго ключа
                    registrat.Check_SessKey(id, out sessionKey_IV, out string nick1, out sessionKey, out timeDech);
                    //проверка действительности сеансовго ключа
                    if (timeDech > timeDech1)
                    {
                        //вывод ID_Key 
                        registrat.Check_Login(nick1, out string reply, out ID_Key, out ID_IV, out byte[] hash);
                        // расшифровка массива
                        crypto.DecryptMsg(sessionKey, message, sessionKey_IV, out message);
                        crypto.DecryptMsg(ID_Key, message, ID_IV, out message);
                        //извлечение длинны ника искомого пользователя
                        unbyte_massiv(message, out byte[] Friend_nick_value, out message);
                        //извлечение ника
                        unbyte_massiv(message, Convert.ToInt16(Encoding.UTF8.GetString(Friend_nick_value)), out byte[] Friend_nick, out BobPublickKey_ID);
                        //поиска данного пользователя в БД
                        registrat.Check_Login(Encoding.UTF8.GetString(Friend_nick), out string reply1, out byte[] ID_Key1, out byte[] ID_IV1, out byte[] hash1);
                        // добавление публичного ключа ника отправителя и ника получателя
                        registrat.addFriendList(nick1, Encoding.UTF8.GetString(Friend_nick), BobPublickKey_ID, 1);
                        //шифрование ответа сервера
                        crypto.EncryptMsg_IV(ID_Key, Encoding.UTF8.GetBytes("Good"), out byte[] repl, ID_IV);
                        crypto.EncryptMsg_IV(sessionKey, repl, out repl, sessionKey_IV);
                        this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(31)), repl);


                    }
                    else
                    {

                        string rep11 = "Пользователя не существует";
                        crypto.EncryptMsg_IV(ID_Key, Encoding.UTF8.GetBytes(rep11), out byte[] reply11, ID_IV);
                        crypto.EncryptMsg_IV(sessionKey, reply11, out reply11, sessionKey_IV);
                        this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(31)), reply11);
                    }
                }
                if (X == 32)
                {

                    unbyte_massiv(message, 1, out byte[] valueid, out message);
                    unbyte_massiv(message, Convert.ToInt16(Encoding.UTF8.GetString(valueid)), out byte[] byteid, out message);
                    int id = Convert.ToInt16(Encoding.UTF8.GetString(byteid));
                    DateTime timeDech = DateTime.Now;
                    DateTime timeDech1 = DateTime.Now;
                    registrat.Check_SessKey(id, out sessionKey_IV, out string nick1, out sessionKey, out timeDech);
                    if (timeDech > timeDech1)
                    {
                        registrat.Check_Login(nick1, out string reply, out ID_Key, out ID_IV, out byte[] hash);
                        crypto.DecryptMsg(sessionKey, message, sessionKey_IV, out message);
                        crypto.DecryptMsg(ID_Key, message, ID_IV, out message);
                        unbyte_massiv(message, 140, out byte[] bobpub, out byte[] nickf);
                        registrat.Check_Login(Encoding.UTF8.GetString(nickf), out string reply1, out byte[] ID_Key1, out byte[] ID_IV1, out byte[] hash1);
                        if (reply1 == "good")
                        {

                            registrat.addFriendList(nick1, Encoding.UTF8.GetString(nickf), bobpub, 1);
                            crypto.EncryptMsg_IV(ID_Key, Encoding.UTF8.GetBytes("Good"), out byte[] repl, ID_IV);
                            crypto.EncryptMsg_IV(sessionKey, repl, out repl, sessionKey_IV);
                            this.rep = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(32)), repl);
                        }

                    }



                }
                if (X == 41)
                {

                    unbyte_massiv(message, 1, out byte[] valueid, out message);
                    unbyte_massiv(message, Convert.ToInt16(Encoding.UTF8.GetString(valueid)), out byte[] byteid, out message);
                    int id = Convert.ToInt16(Encoding.UTF8.GetString(byteid));
                    MainWindow mainw = new MainWindow();
                    mainw.setid(id);
                    DateTime timeDech = DateTime.Now;
                    DateTime timeDech1 = DateTime.Now;
                    registrat.Check_SessKey(id, out sessionKey_IV, out string nick1, out sessionKey, out timeDech);
                    registrat.Check_Login(nick1, out string reply, out ID_Key, out ID_IV, out byte[] hash);
                    crypto.DecryptMsg(sessionKey, message, sessionKey_IV, out message);
                    crypto.DecryptMsg(ID_Key, message, ID_IV, out message);
                    unbyte_massiv(message, 2, out byte[] leghtnick, out byte[] message1);
                    unbyte_massiv(message1, Convert.ToInt16(UTF8Encoding.UTF8.GetString(leghtnick)), out byte[] nickf, out message1);
                    unbyte_massiv_IV(message1, out byte[] ivf, out message1);
                    registrat.savemassage(nick1, UTF8Encoding.UTF8.GetString(nickf), message1, ivf, message1.Length);
                    ost = 0;
                    this.rep = Encoding.UTF8.GetBytes("Все");
                }

                return ost;
            }
            public byte[] GetTypeM()
            {
                return rep;
            }
        }

        private void viewListUsersButt_Click(object sender, RoutedEventArgs e)
        {
            BdClass bd = new BdClass();
            listFriendWindow listb = new listFriendWindow();
            listb.Show();
        }
    }
}
