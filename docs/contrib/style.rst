.. _Coding Style:

Coding Style (C++)
==================

This is an overview of the coding conventions we use when writing C++
code for the Open Chemistry projects. The style is based largely on the
`Qt <https://wiki.qt.io/Qt_Coding_Style>`__ and
`KDE <https://community.kde.org/Policies/Library_Code_Policy>`__ styles.

Code formatting is enforced through use of the clang-format tool.

Indentation
^^^^^^^^^^^^

-  2 spaces are used for indentation
-  Spaces, not tabs!

.. _line_width:

Line Width
^^^^^^^^^^^^

-  Keep lines of source code to less than 80 characters wide.

.. _declaring_variables:

Declaring Variables
^^^^^^^^^^^^^^^^^^^^

-  Declare each variable on a separate line
-  Avoid abbreviations (e.g. "a", "nmbr") where possible
-  Single character variable names are fine for counters, temporary
   variables etc where the purpose is obvious
-  Wait until a variable is needed to declare it, don't keep unused ones
   around

.. code:: cpp

     // Incorrect
     int nmbr, f;

     // Correct
     int number;
     int result;

-  Variables and function names start with a lower case letter, with
   other words using camel case
-  Abbreviated names should be avoided
-  Acronyms are camel-cased (e.g. CmlFormat, not CMLFormat)

.. code:: cpp

     // Incorrect
     double Cntr;
     std::string rawXML;
     char LIST_DELIMITER = '\t';

     // Correct
     double center;
     std::string rawXml;
     char listDelimiter = '\t';

-  Class names always start with an upper-case letter
-  Public classes should be placed inside the appropriate namespace
-  Member variables should start with m\_

Whitespace
^^^^^^^^^^

-  Use blank lines to group statements together where appropriate
-  Only use a single blank line
-  Always use a single space after a keyword and before a curly brace

.. code:: cpp

   // Wrong
   if(blah){
     explode();
     return 5;
   }

   // Correct
   if (blah) {
     explode();
     return 5;
   }

-  For pointers or references, always use a single space between the
   type and the '*' or '&', but no space between that character and the
   variable name.

.. code:: cpp

     char *x;
     const std::string &myString;
     const char * const y = "whoah";

-  Surround binary operators with spaces
-  No space after a cast
-  Avoid the use of C-style casts

.. code:: cpp

     // Incorrect
     char* memoryBlock = (char*) malloc(data.size());
     // Correct
     char *memoryBlock = reinterpret_cast<char *>(malloc(data.size()));

Braces
^^^^^^^

-  The left curly brace normally goes on the same line as the start of
   the statement

.. code:: cpp

     //Incorrect
     if (foo)
     {
       run();
       break;
     }

     // Correct
     if (foo) {
       run();
       break;
     }

-  Exception: if this is class declarations and function
   implementations. The left brace always goes on the start of a line
   there

.. code:: cpp

     void myFun(const std::string &name)
     {
       std::cout << "Supplied name: " << name << std::endl;
     }

     class Bar
     {
     public:
       Bar();
     };

-  Use curly braces when the body of a conditional contains more than
   one line, and also if a single statement is complex

.. code:: cpp

     // Incorrect
     if (!correct) {
       return false;
     }

     for (int i = 0; i < 42; ++i) {
       var += i;
     }

     // Correct
     if (!correct)
       return false;

     for (int i = 0; i < 42; ++i)
       var += i;

-  Exception: Use curly braces if the parent statement does not fit on
   one line/wraps

.. code:: cpp

     // Correct
     if (!correct || !isValid
         || !aGoodDay) {
       return false;
     }

-  Exception: Use curly braces in any if, then, else blocks where any of
   the elements cover several lines

.. code:: cpp

     // Incorrect
     if (!correct)
       return false;
     else {
       ++counter;
       return true;
     }
     
     // Correct
     if (!correct) {
       return false;
     }
     else {
       ++counter;
       return true;
     }

     // Incorrect
     if (a)
       if (b)
         return true;
       else
         return false;
     
     // Correct
     if (a) {
       if (b)
         return true;
       else
         return false;
     }

-  Use curly braces when the body is empty.

.. code:: cpp

     // Incorrect
     while (true);
     
     // Correct
     while (true) {}

Parentheses
^^^^^^^^^^^^

-  Parentheses should be used to group expressions, and to make the
   intent clearer

.. code:: cpp

     // Incorrect
     if (a && b || c)

     // Correct
     if ((a && b) || c)

     // Incorrect
     x = a + b & c;

     // Correct
     x = (a + b) & c;

.. _switch_statements:

Switch Statements
^^^^^^^^^^^^^^^^^^

-  The case labels should be in the same column as the switch
-  Every case must have a break/return statement at the end, or a
   comment to indicate the omission
-  Exception: Another case follows immediately

.. code:: cpp

     switch (myEnum) {
     case LINE:
       drawLine();
       break;
     case POINT:
     case VERTEX:
       drawDot();
     // Fall through to default.
     default:
       drawDefault();
       break;
     }

.. _line_breaks:

Line Breaks
^^^^^^^^^^^^

-  Keep lines shorter than 80 characters; insert breaks if necessary
-  Commas go at the end of a broken line
-  Operators go at the beginning of a new line

.. code:: cpp

     // Correct
     if (veryLongExpression()
         && anotherEvenLongerExpression()
         && justWhenYouThoughtItCouldntGetLonger()) {
       doSomething();
     }
     Eigen::Vector3d position(currentPosition.x() + offset,
                              currentPosition.y() + offset,
                              0);

.. _inheritance_and_the_virtual_keyword:

Inheritance and the "virtual" Keyword
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  When reimplementing a virtual method, do not put the "virtual"
   keyword in the header

.. _referencing_members:

Referencing Members
^^^^^^^^^^^^^^^^^^^^

-  The use of this-> is discouraged. The use of the m\_ prefix should
   make it clear that a member variable is being referenced.

.. _file_naming:

File Naming
^^^^^^^^^^^^

-  All file names should be lower-case.
-  C++ source files should have a .cpp extension.
-  C++ header files should have a .h extension.

.. _general_exception:

Breaking Rules
^^^^^^^^^^^^^^^^^

-  As with Qt, and others, feel free to break a rule if it makes your
   code look bad!
