/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2018, CESAR. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>

#define CE_PIN		9
#define CSN_PIN		10

#define DATAOUT		11
#define DATAIN		12
#define SPICLOCK	13
#define PIN_ECHO	6
#define PIN_TRIGGER	7

const uint64_t pipe = 0xE8E8F0F0E3LL;

RF24 radio(CE_PIN, CSN_PIN);

void setup()
{
	pinMode(DATAOUT, OUTPUT);
	pinMode(DATAIN, INPUT);
	pinMode(SPICLOCK,OUTPUT);
	pinMode(CE_PIN,OUTPUT);
	pinMode(CSN_PIN,OUTPUT);
	pinMode(PIN_ECHO, INPUT);
	pinMode(PIN_TRIGGER, OUTPUT);

	Serial.begin(9600);

	radio.begin();
	radio.setCRCLength(RF24_CRC_DISABLED);
	radio.openReadingPipe(1,pipe);
	radio.startListening();
	radio.setPALevel(RF24_PA_MAX);
	radio.setDataRate(RF24_250KBPS);
	radio.enableDynamicPayloads();
}

void loop()
{
	byte receivedPayload[32];
	int dlen, len;

	if (!radio.available())
		return;

	dlen = radio.getDynamicPayloadSize();

	receivedPayload[0] = 0x01;
	receivedPayload[1] = 0x02;
	receivedPayload[2] = 0x03;
	receivedPayload[3] = 0x04;
	receivedPayload[4] = 0x05;

	radio.read(&receivedPayload[6],dlen);

	receivedPayload[5] = dlen;
	len = dlen + 6;
	Serial.write(receivedPayload, len);
}
