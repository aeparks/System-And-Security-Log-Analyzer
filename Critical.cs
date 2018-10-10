/* Aaron Parks
 * Assignment 4: "Create A Security Tool"
 * CSS 537 - Network and Internet Security
 * University of Washington | Bothell
 * Winter 2016
 *
 * --- 'Critical' Form ---
 * This is a form object that's invoked by the main form of the SALS program. It's a
 * simple windows that only has text box to display information regarding critical
 * event types and a button to close the window.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;

namespace SALSProgram {
   public partial class Critical : Form {
      string messages = string.Empty;

      //default constructor
      public Critical() {
         InitializeComponent();
      }

      public Critical(string param) {
         InitializeComponent();
         messages = param;
         //invokes 'displayCriticalEvents' function when form loads
         Load += new EventHandler(this.displayCriticalEvents);
      }

	  //'messages' string was formatted before hand in 'SALSMain'
      private void displayCriticalEvents(object sender, EventArgs e) {
         this.textBox.Text = messages;
      }

      private void closeCritical_Click(object sender, EventArgs e) {
         this.Close();
      }

   }
}
