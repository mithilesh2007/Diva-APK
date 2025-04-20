### Insecure Logging

```jsx
* hint is given that insecure logging occur when developers intentionally log sensitive information such as credentials session ids financial details etc
```

- when ever we enter our credit card number and clicking check out button we are getting a toast message as “an error occurred please try again” . but in the code when ever we click the check out button the information is sent to the log cat which can be accessed by any one

```jsx
public class LogActivity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_log);
    }

    public void checkout(View view) {
        EditText cctxt = (EditText) findViewById(R.id.ccText);
        try {
            processCC(cctxt.getText().toString());
        } catch (RuntimeException e) {
            Log.e("diva-log", "Error while processing transaction with credit card: " + cctxt.getText().toString());
            Toast.makeText(this, "An error occured. Please try again later", 0).show();
        }
    }

    private void processCC(String ccstr) {
        RuntimeException e = new RuntimeException();
        throw e;
    }
}
```

- solution : we can overcome this by removing the log.e

## Hard-coding Issues - Part 1

```jsx
hint:
developers sometimes will hardcode sensitive information for ease
```

- in the code we can see that , the key we are entering is being converted to a string and verifies that of a text . which is visible to every one

```bash
public class HardcodeActivity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hardcode);
    }

    public void access(View view) {
        EditText hckey = (EditText) findViewById(R.id.hcKey);
        if (hckey.getText().toString().equals("vendorsecretkey")) {
            Toast.makeText(this, "Access granted! See you on the other side :)", 0).show();
        } else {
            Toast.makeText(this, "Access denied! See you in hell :D", 0).show();
        }
    }
}
```

## Insecure Data Storage - Part 1

```jsx
hint:
inecure data storage is the result of storing confidential information insecurely on the systen i.e poor encryption plain text, access control issues etc
```

- here when we enter a username and password it is being stored in the internal storage of the mobile. which we can access it by
- commands —>>

```bash
adb shell
cd data/data/jakhar.aseem.diva/shared_prefs
cat jakhar.aseem.diva_preferences.xml
```

```jsx
public class InsecureDataStorage1Activity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_data_storage1);
    }

    public void saveCredentials(View view) {
        SharedPreferences spref = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor spedit = spref.edit();
        EditText usr = (EditText) findViewById(R.id.ids1Usr);
        EditText pwd = (EditText) findViewById(R.id.ids1Pwd);
        spedit.putString("user", usr.getText().toString());
        spedit.putString("password", pwd.getText().toString());
        spedit.commit();
        Toast.makeText(this, "3rd party credentials saved successfully!", 0).show();
    }
}
```

## Insecure Data Storage - Part 2

```jsx
hint :
insecure data storagr is the result of storing confidential information insecurely on the system i.e poor encryption , plain text, access, control issues etc.
```

- here when we enter a username and password it is being stored in the database of that particular app directory. which we can access it by

```bash
adb shell
cd data/data/jakhar.aseem.diva/databases
cat ids2
```

- we know the database name as ids2 because it is given in  the code

```jsx
public class InsecureDataStorage2Activity extends AppCompatActivity {
    private SQLiteDatabase mDB;

    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            this.mDB = openOrCreateDatabase("ids2", 0, null);
            this.mDB.execSQL("CREATE TABLE IF NOT EXISTS myuser(user VARCHAR, password VARCHAR);");
        } catch (Exception e) {
            Log.d("Diva", "Error occurred while creating database: " + e.getMessage());
        }
        setContentView(R.layout.activity_insecure_data_storage2);
    }

    public void saveCredentials(View view) {
        EditText usr = (EditText) findViewById(R.id.ids2Usr);
        EditText pwd = (EditText) findViewById(R.id.ids2Pwd);
        try {
            this.mDB.execSQL("INSERT INTO myuser VALUES ('" + usr.getText().toString() + "', '" + pwd.getText().toString() + "');");
            this.mDB.close();
        } catch (Exception e) {
            Log.d("Diva", "Error occurred while inserting into database: " + e.getMessage());
        }
        Toast.makeText(this, "3rd party credentials saved successfully!", 0).show();
    }
}
```

## Insecure Data Storage - Part 3

```jsx
hint:
insecure data storage us the result of storing confidential information insecurely on the system i.e poor encryption , plain text, access control issues etc.
```

- The user name and password are being stored in the file created int the app directory named uinfo,temp (given in the code)

```jsx
public class InsecureDataStorage3Activity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_data_storage3);
    }

    public void saveCredentials(View view) {
        EditText usr = (EditText) findViewById(R.id.ids3Usr);
        EditText pwd = (EditText) findViewById(R.id.ids3Pwd);
        File ddir = new File(getApplicationInfo().dataDir);
        try {
            File uinfo = File.createTempFile("uinfo", "tmp", ddir);
            uinfo.setReadable(true);
            uinfo.setWritable(true);
            FileWriter fw = new FileWriter(uinfo);
            fw.write(usr.getText().toString() + ":" + pwd.getText().toString() + "\n");
            fw.close();
            Toast.makeText(this, "3rd party credentials saved successfully!", 0).show();
        } catch (Exception e) {
            Toast.makeText(this, "File error occurred", 0).show();
            Log.d("Diva", "File error: " + e.getMessage());
        }
    }
}
```

## Insecure Data Storage - Part 4

```jsx
hint:
insecure data storage is the result of storing confidential information insecurely on the system i.e. poor encryption , plain text, access control issues etc.
```

- on clicking save we will get an error saying file not saved means the app doesn't have file permissions. we need to enable it from settings
- The username and password are being stored in a file created in the mobile storage
- The file name starts with a dot in front of it “ .uinfo.txt” means it is a hidden folder

```bash
adb shell
cd storage/emulated/0
cat .uinfo.txt
```

- the file name is given in the code

```jsx
public class InsecureDataStorage4Activity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_data_storage4);
    }

    public void saveCredentials(View view) {
        EditText usr = (EditText) findViewById(R.id.ids4Usr);
        EditText pwd = (EditText) findViewById(R.id.ids4Pwd);
        File sdir = Environment.getExternalStorageDirectory();
        try {
            File uinfo = new File(sdir.getAbsolutePath() + "/.uinfo.txt");
            uinfo.setReadable(true);
            uinfo.setWritable(true);
            FileWriter fw = new FileWriter(uinfo);
            fw.write(usr.getText().toString() + ":" + pwd.getText().toString() + "\n");
            fw.close();
            Toast.makeText(this, "3rd party credentials saved successfully!", 0).show();
        } catch (Exception e) {
            Toast.makeText(this, "File error occurred", 0).show();
            Log.d("Diva", "File error: " + e.getMessage());
        }
    }
}
```

## Input Validation Issues - Part 1

```jsx
hint:
improper or no input validation issues arise when the input is not filtered or the validation before using it . when developing components that take input from outside , always validate it. for ease of database , for exaple one of them is admin you  can try searching for admin to test the output
```

- we need to enter a query , so that we should get all the information present in the database .

<aside>
💡

SQL INJECTION —

**SQL Injection** is a type of **security vulnerability** that allows an attacker to interfere with the queries that an application makes to its **database**

Attackers can :

- view data in the database
- modify or delete data
- bypass the authentication
- execute the admin operation on the database
</aside>

- when we enter user name ‘admin’ and password ‘password123’, the database will get the query as below

<aside>
💡

SELECT * FROM users WHERE username = 'admin' AND password = 'password123';

</aside>

- But here we doesn't know the user name so we are giving the user name as ***admin’ or ‘1’=’1***

<aside>
💡

if the username is admin’ or ‘1’=’1 the query to the database is =

SELECT * FROM users WHERE username = 'admin' OR '1'='1’ AND password = 'password123';

</aside>

- so if the username is correct or wrong it will login because 1 is always equal to 1

## Input Validation Issues - Part 2

<aside>
💡

Hint:

Improper or no input validation issue arise when the input is not filtered or validated before using it . When developing components that take input from outside , always validate it .

</aside>

- here we should not enter HTTP matter here , we should enter [file://](file://) matter
- we should access our sensitive information from here

<aside>
💡

search engine can access our sensitive information by [file://](file://) 

</aside>

- here i am accessing file:///data/data/jakhar.aseem.diva/unifo7095106064780821338tmp

```jsx
public class InputValidation2URISchemeActivity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_input_validation2_urischeme);
        WebView wview = (WebView) findViewById(R.id.ivi2wview);
        WebSettings wset = wview.getSettings();
        wset.setJavaScriptEnabled(true);
    }

    public void get(View view) {
        EditText uriText = (EditText) findViewById(R.id.ivi2uri);
        WebView wview = (WebView) findViewById(R.id.ivi2wview);
        wview.loadUrl(uriText.getText().toString());
    }
}
```

## Access Control Issues - Part-1

<aside>
💡

hint;

Components of an app can be accessed from other apps or users if they are not properly protected . Components such as activities , services, content providers are prone to this 

</aside>

- here we should be able to access the API credentials out side the app

<aside>
💡

to access it the bash command is 

```bash
adb shell am start -a jakhar.aseem.diva.action.VIEW_CREDS
```

</aside>

- “jakhar.aseem.diva.action.VIEW_CREDS “ is the name of the activity
- Solution: to prevent this the activity should have “exported = false”

```jsx
public class AccessControl1Activity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control1);
    }

    public void viewAPICredentials(View view) {
        Intent i = new Intent();
        i.setAction("jakhar.aseem.diva.action.VIEW_CREDS");
        if (i.resolveActivity(getPackageManager()) != null) {
            startActivity(i);
        } else {
            Toast.makeText(this, "Error while getting API details", 0).show();
            Log.e("Diva-aci1", "Couldn't resolve the Intent VIEW_CREDS to our activity");
        }
    }
}
```

## Access Control Issues - Part-2

<aside>
💡

Components of an app can be accessed from other apps or users if they are not properly protected and some may also accept  external inputs. Components such as activities, services , content providers are prone to this

</aside>

- when we register in TVEETER app the app gives us a pin .
- we need to enter the pin when we click on vie API credentials . Then the app shows us our username and password
- here we should be able to access it from outside the app

<aside>
💡

to access it the bash command it 

```bash
adb shell am start -a jakhar.aseem.diva.action.VIEW_CREDS2 --ez check_pin false
```

</aside>

- —ez is used when we are dealing with boolean

```jsx
public class AccessControl2Activity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control2);
    }

    public void viewAPICredentials(View view) {
        RadioButton rbregnow = (RadioButton) findViewById(R.id.aci2rbregnow);
        Intent i = new Intent();
        boolean chk_pin = rbregnow.isChecked();
        i.setAction("jakhar.aseem.diva.action.VIEW_CREDS2");
        i.putExtra(getString(R.string.chk_pin), chk_pin);
        if (i.resolveActivity(getPackageManager()) != null) {
            startActivity(i);
        } else {
            Toast.makeText(this, "Error while getting Tveeter API details", 0).show();
            Log.e("Diva-aci1", "Couldn't resolve the Intent VIEW_CREDS2 to our activity");
        }
    }
}
```

- we are retrieving the content from check_pin stored in string.xml stored in resources folder
- then the contents from the check_pin is passed to chk_pin variable

## Access Control Issues - Part-3

<aside>
💡

Components of an app can be accessed from other apps or users if they are not properly protected and some may also accept  external inputs. Components such as activities, services , content providers are prone to this

</aside>

- when we create a pin it is being stored in a variable called pkey 
`spedit.putString(getString(R.string.pkey), pin)`
- when we are entering the pin it is being fetched from the pkey and verifies it with the user entered pin

```jsx
 String userpin = pinTxt.getText().toString();
if (userpin.equals(pin))
```

- we are calling query() to :

<aside>
💡

Ask the `NotesProvider` for all saved notes (title and content) and get a `Cursor` pointing to that data, which will be displayed in a `ListView`.

</aside>

- here the NotesProvider has the Content_URI

```jsx
    static final Uri CONTENT_URI = Uri.parse("content://jakhar.aseem.diva.provider.notesprovider/notes");
```

- we are accessing the private notes by

```bash
adb shell content query --uri content://jakhar.aseem.diva.provider.notesprovider/notes
```

```jsx
public class AccessControl3NotesActivity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control3_notes);
    }

    public void accessNotes(View view) {
        EditText pinTxt = (EditText) findViewById(R.id.aci3notesPinText);
        Button abutton = (Button) findViewById(R.id.aci3naccessbutton);
        SharedPreferences spref = PreferenceManager.getDefaultSharedPreferences(this);
        String pin = spref.getString(getString(R.string.pkey), "");
        String userpin = pinTxt.getText().toString();
        if (userpin.equals(pin)) {
            ListView lview = (ListView) findViewById(R.id.aci3nlistView);
            Cursor cr = getContentResolver().query(NotesProvider.CONTENT_URI, new String[]{"_id", "title", "note"}, null, null, null);
            String[] columns = {"title", "note"};
            int[] fields = {R.id.title_entry, R.id.note_entry};
            SimpleCursorAdapter adapter = new SimpleCursorAdapter(this, R.layout.notes_entry, cr, columns, fields, 0);
            lview.setAdapter((ListAdapter) adapter);
            pinTxt.setVisibility(4);
            abutton.setVisibility(4);
            return;
        }
        Toast.makeText(this, "Please Enter a valid pin!", 0).show();
    }
}
```

## Hardcoding Issues - Part-2

```jsx
hint:
Developers sometimes will hardcore sensitive information for ease
```

- here we need to enter a vendor key to get access
- under the access method we can see that the key is being fetched from the DivaJni class

```jsx
public class Hardcode2Activity extends AppCompatActivity {
    private DivaJni djni;

    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.BaseFragmentActivityDonut, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hardcode2);
        this.djni = new DivaJni();
    }

    public void access(View view) {
        EditText hckey = (EditText) findViewById(R.id.hc2Key);
        if (this.djni.access(hckey.getText().toString()) != 0) {
            Toast.makeText(this, "Access granted! See you on the other side :)", 0).show();
        } else {
            Toast.makeText(this, "Access denied! See you in hell :D", 0).show();
        }
    }
}
```

- in the DivaJni class the access method which will access the string attributes
- we can see that the library name is libdivajni

```jsx
package jakhar.aseem.diva;

/* loaded from: classes.dex */
public class DivaJni {
    private static final String soName = "divajni";

    public native int access(String str);

    public native int initiateLaunchSequence(String str);

    static {
        System.loadLibrary(soName);
    }
}
```

- then we need to extract the [libdivajni.so](http://libdivajni.so) file and reverse it using ghidra
- then in ghidra in functions i clicked on OnLoad because it loads the string here .

![image.png](attachment:3fc64eba-53be-4a75-ba86-b42bf84e03df:image.png)
![image](https://github.com/user-attachments/assets/bbd43592-89b1-41e1-9065-f025660bceca)

## Input Validation Issues - Part-3

```
hint:
Improper or no input validation issue arise when the input is not filterd or validated before using it. When developin components that take input from outside always validate it . This is a classic memmory corruption vulnerable. If you can get the code execution, I would love to here from you. I dont expect anyone to go that far through
```

- here we need to give a input do that we should be able to crash the app

<aside>
💡

FUZZING

**fuzzing** (or **fuzz testing**) is a technique used to discover bugs, crashes, and vulnerabilities in software by **feeding it lots of random, malformed, or unexpected inputs**.

</aside>

- If we enter random long numbers we should be able to crash the app because the app cannot handle long inputs (here the limit was 31 characters)

