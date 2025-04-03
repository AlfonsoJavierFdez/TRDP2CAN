
#include <stdint.h>
#include <stdbool.h>
#include <Arduino.h>
#include <Wire.h>
#include <SPI.h>
#include <Arduino_PortentaMachineControl.h>

static uint32_t CAN_ID = 100ul;
unsigned long currentTime = 0, previousTime = 0, previousTimeCAN = 0;  
unsigned long timeIntervalCAN =500; // time period between CAN msg (microseconds)
unsigned long timeInterval =5000; // time period between modification of the messages
uint8_t CANbyte[64],CANsend[64];
uint8_t msg_data[8];
uint64_t blocks[8]; // Arreglo para almacenar los bloques de 8 bytes

void setup() {
  Serial.begin(115200);

  if (!MachineControl_CANComm.begin(CanBitRate::BR_250k)) {
    Serial.println("CAN init failed.");
    while(1) ;
  }

}

void loop() {
  currentTime=micros(); // or millis() if needed more than 70 minutes of continuous operation
  if (currentTime - previousTime > timeInterval) {

    for(uint8_t i=0; i<sizeof(CANbyte); i++)CANbyte[i]+=1;
    Serial.print("New data pkg arrived: ");
    for(uint8_t j=0; j<8; j++)
      for(uint8_t i=0; i<8; i++) CANbyte[i+(8*j)]+=j;
    for(uint8_t i=0; i<sizeof(CANbyte); i++){
     Serial.print(CANbyte[i]);
     Serial.print(",");
    }

    
    previousTime = currentTime;
  }


  if (currentTime - previousTimeCAN > timeIntervalCAN) {
    
    /* Assemble the CAN message */
    for(uint8_t i=0; i<8; i++){
      msg_data[i] = CANsend[i+8*(CAN_ID-100)] & 0xFF;
    }
    CanMsg msg(CAN_ID, sizeof(msg_data), msg_data);
    /* Transmit the CAN message */
    int const rc = MachineControl_CANComm.write(msg);
    if (rc <= 0) {
      Serial.print("CAN write failed with error code: ");
      Serial.println(rc);
      while(1) ;
    }
    /* Increase the message counter */
    CAN_ID++;
    Serial.print("CAN msg sent with: CAN_ID=");
    Serial.print(CAN_ID);
    Serial.print(" data=");
    for(uint8_t i=0; i<8; i++){
      Serial.print(msg_data[i]);
      Serial.print(",");
    }
    Serial.println(" ");

    if(CAN_ID-100>=(sizeof(CANbyte)/8)){
      CAN_ID=100ul;
      for(uint8_t i=0; i<sizeof(CANbyte); i++) CANsend[i] = CANbyte[i];
    }
    previousTimeCAN = currentTime;
  }

}