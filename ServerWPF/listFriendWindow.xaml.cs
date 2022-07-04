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
using System.Windows.Shapes;

namespace ServerWPF
{
    /// <summary>
    /// Логика взаимодействия для listFriendWindow.xaml
    /// </summary>
    public partial class listFriendWindow : Window
    {
        public listFriendWindow()
        {
            InitializeComponent();
        }

        private void list_load(object sender, RoutedEventArgs e)
        {
            BdClass bd = new BdClass();
            bd.viewUsers(out List<string> nicks);
            foreach (string nick in nicks)
            {
                listUsersBox.Items.Add(nick);
            }
                
        }
    }
}
