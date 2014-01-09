/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <stdio.h>
#include <algorithm>

class SomeEvent {
 public:
  void SetHandlerClass(class MyNetworkClass *owner) { owner_ = owner; }
 private:
  class MyNetworkClass *owner_;
};

class MyNetworkClass {
 public:
  MyNetworkClass() : event_(NULL) { }

  ~MyNetworkClass() { delete event_; }

  void HandleEvent(SomeEvent *new_event) {
    assert(event_ == NULL);
    event_ = new_event;
    event_->SetHandlerClass(this);
  }

 private:
  SomeEvent *event_;
};

SomeEvent *event_queue = NULL;  // a queue of size 1 :)

void HandleEvents(MyNetworkClass *n) {
  SomeEvent *new_event = NULL;
  std::swap(new_event, event_queue);  // queue.pop()
  if (new_event)
    n->HandleEvent(new_event);
}

void SomeEventHappened() {
  assert(event_queue == NULL);  // queue not full
  event_queue = new SomeEvent();
}

void FreeUnhandledEvents() {
   delete event_queue;
}

MyNetworkClass *CreateNetwork() {
  return new MyNetworkClass();
}

int main() {
  SomeEventHappened();

  MyNetworkClass *mnc = CreateNetwork();
  // ...
  HandleEvents(mnc);
  // ...
  FreeUnhandledEvents();

  //delete mnc;  // Uncomment to avoid leaks.
  printf("done\n");
}
