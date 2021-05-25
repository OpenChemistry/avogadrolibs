.. _Code Documentation:

Documenting Code
=================

We use `Doxygen <http://www.doxygen.org/>`__ to generate documentation,
and make use of the JavaDoc style. They go in the header next to the
declaration, all classes should have at a minimum a brief description
with one or two sentences explaining what the intended purpose of the
class is.

.. code:: cpp

   /**
    * @brief Your documentation goes here.
    */
   void doSomething();

.. _class_descriptions:

Class Descriptions
^^^^^^^^^^^^^^^^^^^

-  Minimum of a brief overview of the class
-  Add include path for users of the class
-  If appropriate, point out alternate/similar classes
-  Ideally give some simple examples of using the class

   -  Demonstrate core functionality in the simplest way possible

.. code:: cpp

   namespace MoleQueue
   {
   /**
    * @class JsonRpcClient jsonrpcclient.h <molequeue/client/jsonrpcclient.h>
    * @brief The JsonRpcClient class is used by clients to submit calls to an RPC
    * server using JSON-RPC 2.0.
    * @author Marcus D. Hanwell
    *
    * Provides a simple Qt C++ API to make JSON-RPC 2.0 calls to an RPC server. To
    * create a client connection and call a method the following should be done:
    *
    @code
    #include <molequeue/client/jsonrpcclient.h>

    MoleQueue::JsonRpcClient *client = new MoleQueue::JsonRpcClient(this);
    client->connectToServer("MyRpcServer");
    QJsonObject request(client->emptyRequest());
    request["method"] = QLatin1String("listQueues");
    client->sendRequest(request);
    @endcode
    *
    * You should connect to the appropriate signals in order to act on results,
    * notifications and errors received in response to requests set using the
    * client connection.
    */

   class JsonRpcClient : public QObject
   {
   };

   } // End namespace MoleQueue

.. _function_descriptions:

Function Descriptions
^^^^^^^^^^^^^^^^^^^^^^

-  @brief descriptions:

   -  Use complete sentences

-  Constructors should be more that "Constructor", such as "Constructs
   the ... with ..."
-  Use complete sentences to describe parameters

.. code:: cpp

   /**
    * @brief Set the input file for the job.
    * @param fileName The file name as it will appear in the working directory.
    * @param contents The contents of the file specified.
    * @return true if the input file was successfully set, false otherwise.
    */
   bool setInputFile(const QString &fileName, const QString &contents);
