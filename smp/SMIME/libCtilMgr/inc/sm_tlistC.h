
//_BEGIN_CTIL_NAMESPACE 
//using SNACC::CSM_Exception;

#ifndef _sm_tlistC_h
#define _sm_tlistC_h 1

// source taken from snacc generated list code and modified to be template
template <class T>class CSM_ListC: public List<T>
{
protected:

public:
   CSM_ListC() {};
   CSM_ListC(CSM_ListC<T> &Tref): List<T>(Tref) {};
   CSM_ListC(List<T> &Tref): List<T>(Tref) {};
   virtual ~CSM_ListC() {};

   T *SetCurrElmt (unsigned long index) 
   { List<T>::SetCurrElmt(index); return Curr(); };
   T *SetCurrToFirst() { List<T>::SetCurrToFirst(); return Curr(); };
   // reading member fcns
   int CountL() const { return Count(); }

   T *FirstL() /*RWC;const*/ { return List<T>::First(); }
   T *LastL() /*RWC;const*/ { return List<T>::Last(); }
   T *Curr() /*RWC;const*/ { return List<T>::Curr(); }
   T *NextL() /*RWC;const*/ { return List<T>::Next(); }
   T *PrevL() /*RWC;const*/ { return List<T>::Prev(); }

   // routines that move the curr elmt
   //T *GoNext() { if (curr) curr = curr->next; return Curr(); }
   //T *GoPrev() { if (curr) curr = curr->prev; return Curr(); }

   // write & alloc fcns - returns new elmt
   T* AppendL() {return Append(); } // add elmt to end of list
   void AppendL(T *t); // add elmt to end of list
   void AppendL(CSM_ListC<T> *list);
   //T* InsertBefore(); //insert elmt before current elmt
   //T* InsertAfter(); //insert elmt after current elmt

   // removing the current elmt from the list
   void RemoveCurrNodeOnlyFromList();
   //CSM_ListC<T> &operator = (CSM_ListC<T> &Tref);

};


// add provided elmt to end of list
template <class T> void
CSM_ListC<T>::AppendL(T* t)
{
   typename CSM_ListC<T>::ListElmt *newElmt;
   newElmt  = new (typename CSM_ListC<T>::ListElmt);
   newElmt->elmt  = t;
   newElmt->next = NULL;
   if (last == NULL)
   {
      newElmt->prev = NULL;
      first = last  = newElmt;
   }
   else
   {
      newElmt->prev = last;
      last->next    = newElmt;
      last          = newElmt;
   }
   count++;
   curr = newElmt;
} // CSM_ListC::Append

// append a list to this list
template <class T> void
CSM_ListC<T>::AppendL(CSM_ListC<T> *list)
{
   T *add;
   for (add = list->SetCurrToFirst(); add != NULL;
         add = list->GoNext())
      AppendL(add);
}

// alloc new list elmt, put at begining of list
//  and return the component type
/*template <class T> T*
CSM_ListC<T>::Prepend()
{
   SMListElmt *newElmt;
   newElmt  = new SMListElmt;
   newElmt->elmt = new T;
   newElmt->prev = NULL;
   if (first == NULL)
   {
      newElmt->next = NULL;
      first = last  = newElmt;
   }
   else
   {
      newElmt->next = first;
      first->prev   = newElmt;
      first         = newElmt;
   }
   count++;
   return (curr = newElmt)->elmt;
} // CSM_ListC::Prepend

// alloc new list elmt, insert it before the
// current element and return the component type
// if the current element is null, the new element
// is placed at the beginning of the list.
template <class T> T*
CSM_ListC<T>::InsertBefore()
{
   SMListElmt *newElmt;
   newElmt  = new SMListElmt;
   newElmt->elmt = new T;
   if (curr == NULL)
   {
      newElmt->next = first;
      newElmt->prev = NULL;
      first = newElmt;
      if (last == NULL)
         last = newElmt;
   }
   else
   {
      newElmt->next = curr;
      newElmt->prev = curr->prev;
      curr->prev = newElmt;
      if (curr == first)
         first = newElmt;
      else
         newElmt->prev->next = newElmt;
   }
   count++;
   return (curr = newElmt)->elmt;
} // CSM_ListC::InsertBefore

// alloc new list elmt, insert it after the
// current element and return the component type
// if the current element is null, the new element
// is placed at the end of the list.
template <class T> T*
CSM_ListC<T>::InsertAfter()
{
   SMListElmt *newElmt;
   newElmt  = new SMListElmt;
   newElmt->elmt = new T;
   if (curr == NULL)
   {
      newElmt->prev = last;
      newElmt->next = NULL;
      last = newElmt;
      if (first == NULL)
         first = newElmt;
   }
   else
   {
      newElmt->prev = curr;
      newElmt->next = curr->next;
      curr->next = newElmt;
      if (curr == last)
         last = newElmt;
      else
         newElmt->next->prev = newElmt;
   }
   count++;
   return (curr = newElmt)->elmt;
} // CSM_ListC::InsertAfter
*/
template <class T> void
CSM_ListC<T>::RemoveCurrNodeOnlyFromList()
{
   typename CSM_ListC<T>::ListElmt *del_elmt;

   if (curr != NULL)
   {
      del_elmt = curr;
      count--;

      if (count == 0)
         first = last = curr = NULL;
      else if (curr == first)
      {
         curr = first= first->next;
         first->prev = NULL;
      }
      else if (curr == last)
      {
         curr = last = last->prev;
         last->next = NULL;
      }
      else
      {
         curr->prev->next = curr->next;
         curr->next->prev = curr->prev;
      }

      delete del_elmt;
   }
}
/*
template <class T>
CSM_ListC<T> &CSM_ListC<T>::operator = (CSM_ListC<T> &Tref)
{
   T *add;
   T *add2;
   for (add = Tref.SetCurrToFirst(); add != NULL;
         add = Tref.GoNext())
   {
      add2 = new T;
      *add2 = (*add);
      AppendL(add2);
   }
   return *this;
}   
*/

#endif //_sm_tlistC_h

//_END_CTIL_NAMESPACE 

// EOF sm_list.cpp
