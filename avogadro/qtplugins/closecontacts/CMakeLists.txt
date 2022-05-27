avogadro_plugin(CloseContacts
  "Predictive close-contact rendering"
  ScenePlugin
  closecontacts.h
  CloseContacts
  closecontacts.cpp
  "")

target_link_libraries(CloseContacts PRIVATE AvogadroRendering)
