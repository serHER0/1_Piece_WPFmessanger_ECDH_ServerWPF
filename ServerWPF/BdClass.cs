using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace ServerWPF
{
    internal class BdClass
    {
        SqlConnection sqlConnection;
        string Connection_String = @"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=D:\Programmirpvan\finalDiplom\framework\ServerWPF\ServerWPF\DbInfoClient.mdf;Integrated Security=True";


        public void Registration_0(string login, byte[] Hash_User, byte[] ID_User, byte[] IV)
        {


            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();

            SqlCommand command = new SqlCommand("INSERT INTO [Users_Info] (login, Hash_User, ID_User, IV)VALUES(@Val1, @val2, @val3, @val4)", sqlConnection);

            command.Parameters.AddWithValue("@val1", login);
            command.Parameters.AddWithValue("@val2", Hash_User);
            command.Parameters.AddWithValue("@val3", ID_User);
            command.Parameters.AddWithValue("@val4", IV);

            command.ExecuteNonQuery();
        }
        public void Check_Login(string log, byte[] hash, byte[] ID_Key, byte[] IV, out string reply)
        {
            string witness = null;
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            //проверка есть ли такой логин в базе данных
            SqlCommand command = new SqlCommand("SELECT login from [Users_Info] where login = @login", sqlConnection);
            command.Parameters.AddWithValue("@login", log);
            try
            {
                sqlReader = command.ExecuteReader();
                while (sqlReader.Read())
                {
                    witness += Convert.ToString(sqlReader["login"]);
                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }

            if (witness == null)
            {
                // если нет то идет сохравнение всех данных пользователя и положительный ответ
                Registration_0(log, hash, ID_Key, IV);
                reply = "registed";
            }
            else
            {
                // если такой логин был найден
                reply = "reload";
            }
        }
        public void Check_Login(string log, out string reply, out byte[] ID_Key, out byte[] IV, out byte[] Hash)
        {
            string witness = null;
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT login, ID_User, IV, Hash_User from [Users_Info] where login = @login", sqlConnection);
            command.Parameters.AddWithValue("@login", log);
            byte[] ID_Key_1 = null;
            byte[] IV_1 = null;
            byte[] Hash1 = null;
            try
            {
                sqlReader = command.ExecuteReader();
                if (sqlReader.Read())
                {
                    witness += Convert.ToString(sqlReader["login"]);
                    ID_Key_1 = (byte[])sqlReader["ID_User"];
                    IV_1 = (byte[])sqlReader["IV"];
                    Hash1 = (byte[])sqlReader["Hash_User"];
                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }

            if (witness == null)
            {
                reply = "login dont registed";
                ID_Key = null;
                IV = null;
                Hash = null;
            }
            else
            {
                reply = "good";
                ID_Key = ID_Key_1;
                IV = IV_1;
                Hash = Hash1;
            }
        }
        public void Check_SessKey(int id, out byte[] IV, out string nick, out byte[] sessKey, out DateTime time)
        {
            byte[] sessKey1 = new byte[64];
            byte[] IV1 = new byte[16];
            string nick1 = null;
            DateTime time1 = DateTime.Now;
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT nick, sesKey, dateDel, IV  FROM [session_keys] where id =@id1", sqlConnection);
            command.Parameters.AddWithValue("@id1", id);
            try
            {
                sqlReader = command.ExecuteReader();
                if (sqlReader.Read())
                {
                    nick1 += Convert.ToString(sqlReader["nick"]);
                    sessKey1 = (byte[])sqlReader["sesKey"];
                    time1 = (DateTime)sqlReader["dateDel"];
                    IV1 = (byte[])sqlReader["IV"];

                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }

            if (nick1 != null)
            {
                nick = nick1;
                sessKey = sessKey1;
                time = time1;
                IV = IV1;
            }
            else
            {
                nick = "Сеансовый ключ не создан";
                sessKey = null;
                time = time1;
                IV = null;
            }


        }
        public void Check_and_add_SessKey_log(string login, byte[] sessKey, DateTime time, byte[] sessionIV, out int id)
        {

            string nick1 = null;
            int id1 = 0;
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT nick from [session_keys] where nick =@nick1", sqlConnection);
            command.Parameters.AddWithValue("@nick1", login);
            try
            {
                sqlReader = command.ExecuteReader();
                if (sqlReader.Read())
                {
                    nick1 += Convert.ToString(sqlReader["nick"]);


                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }

            if (nick1 != null)
            {
                sqlConnection = new SqlConnection(Connection_String);
                sqlConnection.Open();
                SqlCommand command1 = new SqlCommand("DELETE FROM [session_keys] where nick =@nick1", sqlConnection);
                command1.Parameters.AddWithValue("@nick1", nick1);
                command1.ExecuteNonQuery();
                ADDsession_key(sessKey, login, time, sessionIV);

                SqlCommand command2 = new SqlCommand("SELECT id from [session_keys] where nick =@nick1", sqlConnection);
                command2.Parameters.AddWithValue("@nick1", login);

                try
                {
                    sqlReader = command2.ExecuteReader();
                    if (sqlReader.Read())
                    {
                        id1 = Convert.ToInt16(sqlReader["id"]);

                    }
                }
                finally
                {
                    if (sqlReader != null)
                        sqlReader.Close();
                }
            }
            else
            {
                ADDsession_key(sessKey, login, time, sessionIV);

                SqlCommand command2 = new SqlCommand("SELECT id from [session_keys] where nick=@nick1", sqlConnection);
                command2.Parameters.AddWithValue("@nick1", login);

                try
                {
                    sqlReader = command2.ExecuteReader();
                    if (sqlReader.Read())
                    {
                        id1 = Convert.ToInt16(sqlReader["id"]);


                    }
                }
                finally
                {
                    if (sqlReader != null)
                        sqlReader.Close();
                }
            }
            id = id1;

        }
        public void ADDsession_key(byte[] sesKey, string nick, DateTime timeDev, byte[] sessionIV)
        {
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();

            SqlCommand command = new SqlCommand("INSERT INTO [session_keys] (nick, sesKey, dateDel, IV)VALUES(@Val1, @val2, @val4, @val5)", sqlConnection);

            command.Parameters.AddWithValue("@val1", nick);
            command.Parameters.AddWithValue("@val2", sesKey);
            command.Parameters.AddWithValue("@val4", timeDev);
            command.Parameters.AddWithValue("@val5", sessionIV);

            command.ExecuteNonQuery();
        }
        public void addFriendList(string SenNick, string RecNick, byte[] pubKey, int type)
        {
            check_friendReq1(SenNick, RecNick, out byte[] repKey, out string sennick1, out string recnick1);
            if (sennick1 == "Нет")
            {
                sqlConnection = new SqlConnection(Connection_String);
                sqlConnection.Open();
                SqlDataReader sqlReader = null;
                SqlCommand command = new SqlCommand("INSERT INTO [Req_IN_friend] (Sennder, Recipient, PubKey, type)VALUES(@Val1, @val2, @val3, @val4)", sqlConnection);

                command.Parameters.AddWithValue("@val1", SenNick);
                command.Parameters.AddWithValue("@val2", RecNick);
                command.Parameters.AddWithValue("@val3", pubKey);
                command.Parameters.AddWithValue("@val4", type);
                command.ExecuteNonQuery();
            }
            else
            {
                sqlConnection = new SqlConnection(Connection_String);
                sqlConnection.Open();
                SqlCommand command1 = new SqlCommand("DELETE FROM [Req_IN_friend] where Sennder=@snick AND Recipient=@rnick", sqlConnection);
                command1.Parameters.AddWithValue("@snick", SenNick);
                command1.Parameters.AddWithValue("@rnick", RecNick);
                command1.ExecuteNonQuery();


                SqlCommand command = new SqlCommand("INSERT INTO [Req_IN_friend] (Sennder, Recipient, PubKey, type)VALUES(@Val1, @val2, @val3, @val4)", sqlConnection);

                command.Parameters.AddWithValue("@val1", SenNick);
                command.Parameters.AddWithValue("@val2", RecNick);
                command.Parameters.AddWithValue("@val3", pubKey);
                command.Parameters.AddWithValue("@val4", type);
                command.ExecuteNonQuery();
            }

        }
        public void check_friendReq(string nick, int type, out byte[] pubk, out string sennick1, out string recnick1)
        {
            string senNick = null;
            string recNick = null;
            byte[] pubKey = new byte[16];
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT Sennder, Recipient, PubKey from [Req_IN_friend] where Recipient=@recNick AND type = @type", sqlConnection);
            command.Parameters.AddWithValue("@recNick", nick);
            command.Parameters.AddWithValue("@type", type);
            try
            {
                sqlReader = command.ExecuteReader();
                while (sqlReader.Read())
                {
                    senNick += Convert.ToString(sqlReader["Sennder"]);
                    recNick += Convert.ToString(sqlReader["Recipient"]);
                    pubKey = (byte[])sqlReader["Recipient"];
                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }

            if (senNick != null)
            {
                pubk = pubKey;
                sennick1 = senNick;
                recnick1 = recNick;
            }
            else
            {
                pubk = null;
                sennick1 = "Нет";
                recnick1 = null;
            }
        }
        public void check_friendReq1(string Snick, string Rnick, out byte[] pubk, out string sennick1, out string recnick1)
        {
            string senNick = null;
            string recNick = null;
            byte[] pubKey = new byte[16];
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT Sennder, Recipient, PubKey from [Req_IN_friend] where Sennder=@senNick AND Recipient=@recNick ORDER BY Id", sqlConnection);
            command.Parameters.AddWithValue("@senNick", Snick);
            command.Parameters.AddWithValue("@recNick", Rnick);
            try
            {
                sqlReader = command.ExecuteReader();
                while (sqlReader.Read())
                {
                    senNick += Convert.ToString(sqlReader["Sennder"]);
                    recNick += Convert.ToString(sqlReader["Recipient"]);
                    pubKey = (byte[])sqlReader["PubKey"];
                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }

            if (senNick != null)
            {
                pubk = pubKey;
                sennick1 = senNick;
                recnick1 = recNick;
            }
            else
            {
                pubk = null;
                sennick1 = "Нет";
                recnick1 = null;
            }
        }
        private byte[] byte_massiv(byte[] one, byte[] two)
        {
            byte[] mass = new byte[one.Length + two.Length];

            System.Buffer.BlockCopy(one, 0, mass, 0, one.Length);
            System.Buffer.BlockCopy(two, 0, mass, one.Length, two.Length);
            return (mass);
        }
        public void allnews(int id, out List<byte[]> reqFre, out List<byte[]> mess, out string reply)
        {
            reply = "";
            DateTime time1 = DateTime.Now;
            List<byte[]> reqFre1 = new List<byte[]>();
            List<byte[]> mess1 = new List<byte[]>();
            string nick1 = null;
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT nick, dateDel  FROM [session_keys] where id =@id1 ORDER BY Id", sqlConnection);
            command.Parameters.AddWithValue("@id1", id);
            try
            {
                sqlReader = command.ExecuteReader();
                if (sqlReader.Read())
                {

                    nick1 += Convert.ToString(sqlReader["nick"]);
                    time1 = (DateTime)sqlReader["dateDel"];
                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }


            if (time1 > DateTime.Now)
            {
                //запросы в друзья
                SqlDataReader sqlReader1 = null;
                //
                string senNick1 ="";
                SqlCommand command1 = new SqlCommand("SELECT Sennder, PubKey from [Req_IN_friend] where Recipient=@recNick ORDER BY Id",
                    sqlConnection);
                command1.Parameters.AddWithValue("@recNick", nick1);

                try
                {
                    sqlReader1 = command1.ExecuteReader();
                    while (sqlReader1.Read())
                    {
                        senNick1 = Convert.ToString(sqlReader1["Sennder"]);
                        byte[] pubKey = (byte[])sqlReader1["PubKey"];
                        reqFre1.Add(byte_massiv(pubKey, UTF8Encoding.UTF8.GetBytes(senNick1)));



                    }
                }
                finally
                {
                    if (sqlReader1 != null)
                        sqlReader1.Close();
                }

                SqlCommand cmd = new SqlCommand("DELETE from [Req_IN_friend] where Recipient=@recNick", sqlConnection);
                cmd.Parameters.AddWithValue("@recNick", nick1);
                cmd.ExecuteNonQuery();
                // сообщения

                SqlDataReader sqlReader2 = null;
                SqlCommand command2 = new SqlCommand("SELECT Sender, Content, IV, leghtmess from [MessageUsers] where Recipient=@recNick ORDER BY Id",
                    sqlConnection);
                command2.Parameters.AddWithValue("@recNick", nick1);
                byte[] senNick = null;
                try
                {
                    sqlReader2 = command2.ExecuteReader();
                    while (sqlReader2.Read())
                    {
                        senNick = Encoding.UTF8.GetBytes(Convert.ToString(sqlReader2["Sender"]));
                        byte[] content = (byte[])sqlReader2["Content"];
                        byte[] IV = (byte[])sqlReader2["IV"];
                        int leght1 = (int)(sqlReader2["leghtmess"]);
                        // отделение зашифрованного сообщения от мусора
                        unbyte_massiv(content, leght1, out content, out byte[] trash);
                        // объединение массивов публичного ключа и сообщения
                        byte[] mix = byte_massiv(IV, content);
                        //добавление ника отправителя в виде массива байт
                        mix = byte_massiv(senNick, mix);
                        //добавление длинны ника
                        mix = byte_massiv(Encoding.UTF8.GetBytes(Convert.ToString(senNick.Length)), mix);
                        mess1.Add(mix);



                    }
                }
                finally
                {
                    if (sqlReader2 != null)
                        sqlReader2.Close();
                }

                SqlCommand cmd1 = new SqlCommand("DELETE from [MessageUsers] where Recipient=@recNick", sqlConnection);
                cmd1.Parameters.AddWithValue("@recNick", nick1);
                cmd1.ExecuteNonQuery();

                reqFre = reqFre1;
                mess = mess1;
                if(senNick1 != "" && senNick != null)
                {
                    reply = "11";
                }
                if(senNick1 != "" && senNick == null)
                {
                    reply = "10";
                }
                if(senNick1 == "" && senNick != null)
                {
                    reply = "01";
                }
                if(senNick1 == "" && senNick == null)
                {
                    reply = "00";
                }

            }
            else
            {
                reqFre = null;
                mess = null;
                reply = "Сеансовый ключ устарел";
            }
        }
        private void unbyte_massiv(byte[] mass, int lenght, out byte[] one, out byte[] two)
        {

            byte[] mass1 = new byte[mass.Length];
            one = new byte[lenght];
            two = new byte[mass.Length - lenght];
            System.Buffer.BlockCopy(mass, 0, one, 0, lenght);
            System.Buffer.BlockCopy(mass, lenght, two, 0, mass.Length - lenght);


        }
        public void savemassage(string senNick, string recNick, byte[] message, byte[] iv, int leghtmess)
        {
            sqlConnection = new SqlConnection(Connection_String);
            sqlConnection.Open();
            SqlCommand cmd = new SqlCommand("INSERT INTO [MessageUsers] (Sender,Recipient,Content,IV,leghtmess)VALUES(@val1,@val2,@val3,@val4,@val5)", sqlConnection);
            cmd.Parameters.AddWithValue("@val1", senNick);
            cmd.Parameters.AddWithValue("@val2", recNick);
            cmd.Parameters.AddWithValue("@val3", message);
            cmd.Parameters.AddWithValue("@val4", iv);
            cmd.Parameters.AddWithValue("@val5", leghtmess);
            cmd.ExecuteNonQuery();
        }
        public void viewUsers(out List<string> nicks)
        {
            sqlConnection = new SqlConnection(Connection_String);
            List<string> nicks1 = new List<string>();
            sqlConnection.Open();
            SqlDataReader sqlReader = null;
            SqlCommand command = new SqlCommand("SELECT * from [Users_Info] ORDER BY Id", sqlConnection);
            
            try
            {
                sqlReader = command.ExecuteReader();
                while (sqlReader.Read())
                {
                    nicks1.Add(Convert.ToString(sqlReader["login"]));
                    
                }
            }
            finally
            {
                if (sqlReader != null)
                    sqlReader.Close();
            }
            nicks = nicks1;
        }
    }
}
