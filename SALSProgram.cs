/* Aaron Parks
 * Assignment 4: Create A Security Tool
 * CSS 537 - Network and Internet Security
 * University of Washington | Bothell
 * Winter 2016
 * 
 * --- Program Description ---
 * "SASLS: Security And System Log Summarizer"
 * The basic concept behind this program is to provide a smaller, 'light-weight' option for
 * logs on Windows machine.  The provided view is designed to be comprehesive over a provided
 * time frame, but only in a few select aspects.  The goal with this program is not to replace
 * existing log viewers, but to provide the basic information that could be provided by 
 * existing options, but with less feature baggage.
 * 
 * --- Project Timeline / Updates ---
 *   10 March 2016
 *   + win form setup with desired features (i.e. labels, buttons, and other knobs)
 *   
 *   14 March 2016
 *   + able to count the number of events in a log
 *   
 *   16 March 2016
 *   + basic functionality achieved!
 *      - reads in two system logs: 'system' and 'security
 *      - parses those logs and tabulates the number of events
 *      
 *   18 March 2016
 *   + radio buttons now function
 *   + blank form now appears for critical 'View' button
 *    
 * --- Future Features & Updates ---
 *   + using radio buttons to define larger date range
 *      - using a further refinded method to define date range (user entry, perhaps)
 *   + storing previous results and comparing the results to a newer file
 *   + Have all the 'View' buttons function
 *   + export results in 'some' file format
 *   + be able to read in and manipulate more events logs other than 'system' and 'security'
 *   + the ability to select (checkbox, perhaps) which type of events will collected
 *   + delve into how to make it so this program doesn't need be run as an admin
 *      - may not actually be possible because the program reads sensitive info
 *   + do more with uncategorized event types
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
   public partial class SALSMain : Form {
      //for accessing specific logs to load their entries into a collection
      public const int SECURITY = 8;
      public const int SYSTEM = 9;

      EventLog[] localLogs = null;

      //for the information that's displayed when the respective 'View' buttons are clicked
      //string auditFailMessage = string.Empty;
      //string auditSuccMessage = string.Empty;
      string criticalMessage = string.Empty;
      //string errorMessage = string.Empty;
      //string warningMessage = string.Empty;
      //string infoMessage = string.Empty

      public SALSMain() {
         InitializeComponent();
      }
      
      private void beginAnalyzer_Click(object sender, EventArgs e) {
         //load current local machine's event logs into array
         localLogs = EventLog.GetEventLogs(".");

         //time frame checks
         if (radio_forever.Checked)    //no time constraints
            this.parseLogs(localLogs, 1970);
         if (radio_thisYear.Checked)   //current year selected
            this.parseLogs(localLogs, Convert.ToInt32(DateTime.Now.Year));

         /*** more functionality here for future releases  ***/
      }

      /*--- 'parseLogs' ---
       * Will invoke the 'parseSecurityLog' and 'parseSystemLog' helper functions and hand them
       * a 'EventLogEntryCollection' object based upon corresponding index in the parameter
       * 'EventLog[] local machine log array. The parsing work as well as output to the form
       * will be handled by these helper functions. Will also populate message strings for later
       * user with 'View' buttons. */
      private void parseLogs(EventLog[] param, int year) {
         this.parseSecurityLog(param[SECURITY].Entries, year);
         this.parseSystemLog(param[SYSTEM].Entries, year);

         /*** add more logs here for future releases ***/
      }

      /*--- 'parseSecurityLog' ---
       * Helper method for 'parseLogs'. Will iterate through the system log file and count the
       * event types and populate message strings for security events.  Note on 'if' statements
       * in switch: if statement exists because of constraints by radio buttons.  If 'all time'
       * is selected, the year passed to the function '1970'.  If 'this year' is selctred, the
       * current year (using the DateTime object) converted to an integer is passed to the
       * function. */
      private void parseSecurityLog(EventLogEntryCollection securityCollection, int year) {
         uint a_success = 0;
         uint a_failure = 0;

         //string for any other event types not accounted for
         string alert = string.Empty;
         //for displaying 'alert' string
         DialogResult msgBox;

         /* research conducted for this project suggest there are only two event types:
          * -> 'FailureAudit'
          * -> 'SuccessAudit'
          * Intuition suggests there could be more types, so they will be caught in the
          * 'default' case and displayed as an alert box. */
         foreach (EventLogEntry current in securityCollection) {
            switch (current.EntryType.ToString()) {
               case "FailureAudit":
                  if (year == 1970 || current.TimeGenerated.Year == year) {
                     //auditFailMessage += current.Message + Environment.NewLine;
                     a_failure++;
                  }
                  break;
               case "SuccessAudit":
                  if (year == 1970 || current.TimeGenerated.Year == year) {
                     //auditSuccMessage += current.Message + Environment.NewLine;
                     a_success++;
                  }
                  break;
               default:
                  //other event types will be collected into this string //to be displayed later
                  if (year == 1970 || current.TimeGenerated.Year == year)
                     alert += "Event type: " + current.EntryType.ToString() + Environment.NewLine;
                  break;
            }
         }
         //update text labels with final values
         this.auditSuccTotal.Text = a_success.ToString();
         this.auditFailTotal.Text = a_failure.ToString();

         //check for alert box
         if (!String.IsNullOrEmpty(alert)) {
            msgBox = MessageBox.Show(alert,"Uncategorized Security Events", MessageBoxButtons.OK);
         }
      }

      /*--- 'parseSystemLog' ---
       * Helper method for 'parseLogs'. Will iterate through the system log file and count the
       * event types and populate message strings for system events.  Note on 'if' statements in
       * switch: if statement exists because of time constraints by radio buttons.  If 'all time'
       * is selected, the year passed to the function '1970'.  If 'this year' is selctred, the
       * current year (using the DateTime object) converted to an integer is passed to the
       * function. */
      private void parseSystemLog(EventLogEntryCollection systemCollection, int year) {
         uint critical = 0;
         uint errors = 0;
         uint warning = 0;
         uint info = 0;

         //string for any other event types not accounted for
         string alert = string.Empty;
         //for displaying 'alert' string
         DialogResult msgBox;

         /* research conducted for this project suggests there are only four event types:
          * -> 'Critical'
          * -> 'Error'
          * -> 'Warning'
          * -> 'Information'
          * Other types may exist.  If they do, they will be caught in the 'default' case
          * and displayed in an alert box. */
         foreach (EventLogEntry current in systemCollection) {
            switch (current.EntryType.ToString()) {
               case "0":  //<-- 'critical' event type
                  if (year == 1970 || current.TimeGenerated.Year == year) {
                     //assemble and format data
                     criticalMessage += "Date: " + current.TimeGenerated.ToString() + Environment.NewLine +
										"Event ID: " + current.EventID.ToString() + Environment.NewLine + 
										"Index: " + current.Index.ToString() + Environment.NewLine +
										"Message: " + current.Message.ToString() + Environment.NewLine;
                     criticalMessage += Environment.NewLine;
                     critical++;
                  }
                  break;
               case "Error":
                  if (year == 1970 || current.TimeGenerated.Year == year) {
                     //errorMessage += current.Message + Environment.NewLine;
                     errors++;
                  }
                  break;
               case "Warning":
                  if (year == 1970 || current.TimeGenerated.Year == year) {
                     //warningMessage += current.Message + Environment.NewLine;
                     warning++;
                  }
                  break;
               case "Information":
                  if (year == 1970 || current.TimeGenerated.Year == year) {
                     //infoMessage += current.Message + Environment.NewLine;
                  }
                  break;
               default:
                  //other event types will be collected into this string //to be displayed later
                  if (year == 1970 || current.TimeGenerated.Year == year)
                     alert += "Event type: " + current.EntryType.ToString() + Environment.NewLine;
                  break;
            }
         }
         //update text labels with final values
         this.critTotal.Text = critical.ToString();
         this.errorTotal.Text = errors.ToString();
         this.warnTotal.Text = warning.ToString();
         this.infoTotal.Text = info.ToString();

         //check for alert box
         if (!String.IsNullOrEmpty(alert)){
            msgBox = MessageBox.Show(alert,"Uncategorized System Events", MessageBoxButtons.OK);
         }
      }

      /*--- 'View' button click functions ---
       * Each view button is suppose to open a form with a summarization of the information
       * pertaining to that particular event type (e.g. Critical 'View' button shows information
       * regarding all the events with the 'Critical' event type.  Currently, only one form is
       * implemented (Critical), while the others are not.  This is partially due to time
       * constraints and partially due to code volumne.
       * Note to self: there may be a way alter the background functionality of the this program to
       * eliminate repeated code with these 'click' functions. */
      private void viewAuditFail_Click(object sender, EventArgs e) {
         //AuditFailure a_FailForm = new AuditSuccess();
         //a_FailForm.Show();
      }

      private void viewAuditSucc_Click(object sender, EventArgs e) {
         //AuditSuccess a_SuccForm = new AuditSuccess();
         //a_SuccForm.Show();
      }

      private void viewCrit_Click(object sender, EventArgs e) {
		 //check if logs have been read into collection
         if (localLogs != null) {
            Critical critForm = new Critical(criticalMessage);
            critForm.Show();
         }
         else { //if not, do not call form and instead throw an error message box
            DialogResult warning = MessageBox.Show("Security log not read yet!", "Error", MessageBoxButtons.OK);
         }
      }

      private void viewError_Click(object sender, EventArgs e) {
         //Error errorForm = new Error();
         //errorForm.Show();
      }

      private void viewWarn_Click(object sender, EventArgs e) {
         //Warning warnForm = new Warning();
         //warnForm.Show();
      }

      private void viewInfo_Click(object sender, EventArgs e) {
         //Information infoForm = new Information();
         //infoForm.Show();
      }
   }
}