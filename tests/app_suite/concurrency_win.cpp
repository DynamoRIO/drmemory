/* The code in this file is based on sample code from Microsoft.
 *
 *   Coypright (c) 2010 Microsoft Corporation.  All rights reserved.
 *
 * It is included here under the MICROSOFT LIMITED PUBLIC LICENSE:
 *
 * This license governs use of code marked as "sample" or "example"
 * available on this web site without a license agreement, as provided
 * under the section above titled "NOTICE SPECIFIC TO SOFTWARE AVAILABLE
 * ON THIS WEB SITE." If you use such code (the "software"), you accept
 * this license. If you do not accept the license, do not use the
 * software.
 *
 * 1. Definitions
 *
 * The terms "reproduce," "reproduction," "derivative works," and
 * "distribution" have the same meaning here as under U.S. copyright law.
 *
 * A "contribution" is the original software, or any additions or changes
 * to the software.
 *
 * A "contributor" is any person that distributes its contribution under
 * this license.
 *
 * "Licensed patents" are a contributor's patent claims that read
 * directly on its contribution.
 *
 * 2. Grant of Rights
 *
 * (A) Copyright Grant - Subject to the terms of this license, including
 * the license conditions and limitations in section 3, each contributor
 * grants you a non-exclusive, worldwide, royalty-free copyright license
 * to reproduce its contribution, prepare derivative works of its
 * contribution, and distribute its contribution or any derivative works
 * that you create.
 *
 * (B) Patent Grant - Subject to the terms of this license, including the
 * license conditions and limitations in section 3, each contributor
 * grants you a non-exclusive, worldwide, royalty-free license under its
 * licensed patents to make, have made, use, sell, offer for sale,
 * import, and/or otherwise dispose of its contribution in the software
 * or derivative works of the contribution in the software.
 *
 * 3. Conditions and Limitations
 *
 * (A) No Trademark License- This license does not grant you rights to
 * use any contributors' name, logo, or trademarks.
 *
 * (B) If you bring a patent claim against any contributor over patents
 * that you claim are infringed by the software, your patent license from
 * such contributor to the software ends automatically.
 *
 * (C) If you distribute any portion of the software, you must retain all
 * copyright, patent, trademark, and attribution notices that are present
 * in the software.
 *
 * (D) If you distribute any portion of the software in source code form,
 * you may do so only under this license by including a complete copy of
 * this license with your distribution.  If you distribute any portion of
 * the software in compiled or object code form, you may only do so under
 * a license that complies with this license.
 *
 * (E) The software is licensed "as-is." You bear the risk of using
 * it. The contributors give no express warranties, guarantees or
 * conditions.  You may have additional consumer rights under your local
 * laws which this license cannot change. To the extent permitted under
 * your local laws, the contributors exclude the implied warranties of
 * merchantability, fitness for a particular purpose and
 * non-infringement.
 *
 * (F) Platform Limitation - The licenses granted in sections 2(A) and
 * 2(B) extend only to the software or derivative works that you create
 * that run on a Microsoft Windows operating system product.
 */

/* Concurrency runtime is only available for VS2010+ */
#if _MSC_VER >= 1600

#include <windows.h>
#include "gtest/gtest.h"

#include <ppl.h>
#include <iostream>

using namespace Concurrency;
using namespace std;

// Prints the identifier of the current scheduler to the console.
static void perform_task()
{
   // A task group.
   task_group tasks;

   // Run a task in the group. The current scheduler schedules the task.
   tasks.run_and_wait([] {
      wcout << L"Current scheduler id: " << CurrentScheduler::Id() << endl;
   });
}

// Uses the CurrentScheduler class to manage a scheduler instance.
static void current_scheduler()
{
   // Run the task.
   // This prints the identifier of the default scheduler.
   perform_task();

   // For demonstration, create a scheduler object that uses
   // the default policy values.
   wcout << L"Creating and attaching scheduler..." << endl;
   CurrentScheduler::Create(SchedulerPolicy());

   // Register to be notified when the scheduler shuts down.
   HANDLE hShutdownEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
   CurrentScheduler::RegisterShutdownEvent(hShutdownEvent);

   // Run the task again.
   // This prints the identifier of the new scheduler.
   perform_task();

   // Detach the current scheduler. This restores the previous scheduler
   // as the current one.
   wcout << L"Detaching scheduler..." << endl;
   CurrentScheduler::Detach();

   // Wait for the scheduler to shut down and destroy itself.
   WaitForSingleObject(hShutdownEvent, INFINITE);

   // Close the event handle.
   CloseHandle(hShutdownEvent);

   // Run the sample task again.
   // This prints the identifier of the default scheduler.
   perform_task();
}

// Uses the Scheduler class to manage a scheduler instance.
static void explicit_scheduler()
{
   // Run the task.
   // This prints the identifier of the default scheduler.
   perform_task();

   // For demonstration, create a scheduler object that uses
   // the default policy values.
   wcout << L"Creating scheduler..." << endl;
   Scheduler* scheduler = Scheduler::Create(SchedulerPolicy());

   // Register to be notified when the scheduler shuts down.
   HANDLE hShutdownEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
   scheduler->RegisterShutdownEvent(hShutdownEvent);

   // Associate the scheduler with the current thread.
   wcout << L"Attaching scheduler..." << endl;
   scheduler->Attach();

   // Run the sample task again.
   // This prints the identifier of the new scheduler.
   perform_task();

   // Detach the current scheduler. This restores the previous scheduler
   // as the current one.
   wcout << L"Detaching scheduler..." << endl;
   CurrentScheduler::Detach();

   // Release the final reference to the scheduler. This causes the scheduler
   // to shut down after all tasks finish.
   scheduler->Release();

   // Wait for the scheduler to shut down and destroy itself.
   WaitForSingleObject(hShutdownEvent, INFINITE);

   // Close the event handle.
   CloseHandle(hShutdownEvent);

   // Run the sample task again.
   // This prints the identifier of the default scheduler.
   perform_task();
}

TEST(Concurrency, Scheduler)
{
   // Use the CurrentScheduler class to manage a scheduler instance.
   wcout << L"Using CurrentScheduler class..." << endl << endl;
   current_scheduler();

   wcout << endl << endl;

   // Use the Scheduler class to manage a scheduler instance.
   wcout << L"Using Scheduler class..." << endl << endl;
   explicit_scheduler();
}


#endif /* _MSC_VER >= 1600 */
