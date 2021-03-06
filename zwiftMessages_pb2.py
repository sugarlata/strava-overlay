# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: zwiftMessages.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13zwiftMessages.proto\"\xc6\x03\n\x0bPlayerState\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x11\n\tworldTime\x18\x02 \x01(\x03\x12\x10\n\x08\x64istance\x18\x03 \x01(\x05\x12\x10\n\x08roadTime\x18\x04 \x01(\x05\x12\x0c\n\x04laps\x18\x05 \x01(\x05\x12\r\n\x05speed\x18\x06 \x01(\x05\x12\x14\n\x0croadPosition\x18\x08 \x01(\x05\x12\x12\n\ncadenceUHz\x18\t \x01(\x05\x12\x11\n\theartrate\x18\x0b \x01(\x05\x12\r\n\x05power\x18\x0c \x01(\x05\x12\x0f\n\x07heading\x18\r \x01(\x03\x12\x0c\n\x04lean\x18\x0e \x01(\x05\x12\x10\n\x08\x63limbing\x18\x0f \x01(\x05\x12\x0c\n\x04time\x18\x10 \x01(\x05\x12\x0b\n\x03\x66\x31\x39\x18\x13 \x01(\x05\x12\x0b\n\x03\x66\x32\x30\x18\x14 \x01(\x05\x12\x10\n\x08progress\x18\x15 \x01(\x05\x12\x17\n\x0f\x63ustomisationId\x18\x16 \x01(\x03\x12\x14\n\x0cjustWatching\x18\x17 \x01(\x05\x12\x10\n\x08\x63\x61lories\x18\x18 \x01(\x05\x12\t\n\x01x\x18\x19 \x01(\x02\x12\x10\n\x08\x61ltitude\x18\x1a \x01(\x02\x12\t\n\x01y\x18\x1b \x01(\x02\x12\x17\n\x0fwatchingRiderId\x18\x1c \x01(\x05\x12\x0f\n\x07groupId\x18\x1d \x01(\x05\x12\r\n\x05sport\x18\x1f \x01(\x03\"\xd1\x01\n\x0e\x43lientToServer\x12\x11\n\tconnected\x18\x01 \x01(\x05\x12\x10\n\x08rider_id\x18\x02 \x01(\x05\x12\x12\n\nworld_time\x18\x03 \x01(\x03\x12\x1b\n\x05state\x18\x07 \x01(\x0b\x32\x0c.PlayerState\x12\r\n\x05seqno\x18\x04 \x01(\x05\x12\x0c\n\x04tag8\x18\x08 \x01(\x03\x12\x0c\n\x04tag9\x18\t \x01(\x03\x12\x13\n\x0blast_update\x18\n \x01(\x03\x12\r\n\x05tag11\x18\x0b \x01(\x03\x12\x1a\n\x12last_player_update\x18\x0c \x01(\x03\"\xe2\x01\n\rSegmentResult\x12\n\n\x02id\x18\x01 \x01(\x03\x12\x10\n\x08rider_id\x18\x02 \x01(\x03\x12\x19\n\x11\x65vent_subgroup_id\x18\x06 \x01(\x03\x12\x12\n\nfirst_name\x18\x07 \x01(\t\x12\x11\n\tlast_name\x18\x08 \x01(\t\x12\x17\n\x0f\x66inish_time_str\x18\n \x01(\t\x12\x12\n\nelapsed_ms\x18\x0b \x01(\x03\x12\x12\n\npowermeter\x18\x0c \x01(\x05\x12\x0e\n\x06weight\x18\r \x01(\x05\x12\r\n\x05power\x18\x0f \x01(\x05\x12\x11\n\theartrate\x18\x13 \x01(\x05\"z\n\x0eSegmentResults\x12\x10\n\x08world_id\x18\x01 \x01(\x03\x12\x12\n\nsegment_id\x18\x02 \x01(\x03\x12\x19\n\x11\x65vent_subgroup_id\x18\x03 \x01(\x03\x12\'\n\x0fsegment_results\x18\x04 \x03(\x0b\x32\x0e.SegmentResult\"\x11\n\x0fUnknownMessage1\"\x10\n\x0eUnknownMessage\"\xe1\x01\n\x0eServerToClient\x12\x0c\n\x04tag1\x18\x01 \x01(\x05\x12\x10\n\x08rider_id\x18\x02 \x01(\x05\x12\x12\n\nworld_time\x18\x03 \x01(\x03\x12\r\n\x05seqno\x18\x04 \x01(\x05\x12#\n\rplayer_states\x18\x08 \x03(\x0b\x32\x0c.PlayerState\x12\'\n\x0eplayer_updates\x18\t \x03(\x0b\x32\x0f.UnknownMessage\x12\r\n\x05tag11\x18\x0b \x01(\x03\x12\r\n\x05tag17\x18\x11 \x01(\x03\x12\x10\n\x08num_msgs\x18\x12 \x01(\x05\x12\x0e\n\x06msgnum\x18\x13 \x01(\x05\"u\n\x0fWorldAttributes\x12\x10\n\x08world_id\x18\x01 \x01(\x05\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x0c\n\x04tag3\x18\x03 \x01(\x03\x12\x0c\n\x04tag5\x18\x04 \x01(\x03\x12\x12\n\nworld_time\x18\x06 \x01(\x03\x12\x12\n\nclock_time\x18\x07 \x01(\x03\"$\n\x0eWorldAttribute\x12\x12\n\nworld_time\x18\x02 \x01(\x03\"\xa9\x01\n\x15\x45ventSubgroupProtobuf\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\r\n\x05rules\x18\x08 \x01(\x05\x12\r\n\x05route\x18\x16 \x01(\x05\x12\x0c\n\x04laps\x18\x19 \x01(\x05\x12\x15\n\rstartLocation\x18\x1d \x01(\x05\x12\r\n\x05label\x18\x1e \x01(\x05\x12\x10\n\x08paceType\x18\x1f \x01(\x05\x12\x12\n\njerseyHash\x18$ \x01(\x05\"\xf1\x01\n\x0fRiderAttributes\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\n\n\x02\x66\x33\x18\x03 \x01(\x05\x12;\n\x10\x61ttributeMessage\x18\x04 \x01(\x0b\x32!.RiderAttributes.AttributeMessage\x12\x0f\n\x07theirId\x18\n \x01(\x05\x12\x0b\n\x03\x66\x31\x33\x18\r \x01(\x05\x1ak\n\x10\x41ttributeMessage\x12\x0c\n\x04myId\x18\x01 \x01(\x05\x12\x0f\n\x07theirId\x18\x02 \x01(\x05\x12\x11\n\tfirstName\x18\x03 \x01(\t\x12\x10\n\x08lastName\x18\x04 \x01(\t\x12\x13\n\x0b\x63ountryCode\x18\x05 \x01(\x05\"&\n\x08Profiles\x12\x1a\n\x08profiles\x18\x01 \x03(\x0b\x32\x08.Profile\"\x8a\x03\n\x07Profile\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x11\n\tfirstName\x18\x04 \x01(\t\x12\x10\n\x08lastName\x18\x05 \x01(\t\x12\x0c\n\x04male\x18\x06 \x01(\x05\x12\x0e\n\x06weight\x18\t \x01(\x05\x12\x10\n\x08\x62odyType\x18\x0c \x01(\x05\x12\x13\n\x0b\x63ountryCode\x18\" \x01(\x05\x12\x15\n\rtotalDistance\x18# \x01(\x05\x12\x1c\n\x14totalDistanceClimbed\x18$ \x01(\x05\x12\x1a\n\x12totalTimeInMinutes\x18% \x01(\x05\x12\x16\n\x0etotalWattHours\x18) \x01(\x05\x12\x0e\n\x06height\x18* \x01(\x05\x12\x1d\n\x15totalExperiencePoints\x18. \x01(\x05\x12\x18\n\x10\x61\x63hievementLevel\x18\x31 \x01(\x05\x12\x13\n\x0bpowerSource\x18\x34 \x01(\x05\x12\x0b\n\x03\x61ge\x18\x37 \x01(\x05\x12\x1a\n\x12launchedGameClient\x18l \x01(\t\x12\x19\n\x11\x63urrentActivityId\x18m \x01(\x05\"*\n\x07Vector3\x12\t\n\x01x\x18\x01 \x01(\x02\x12\t\n\x01y\x18\x02 \x01(\x02\x12\t\n\x01z\x18\x03 \x01(\x02\"\xad\x01\n\nPlayerInfo\x12\n\n\x02id\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\x1a\n\x08position\x18\x03 \x01(\x0b\x32\x08.Vector3\x12\x0f\n\x07profile\x18\x05 \x01(\t\x12\x0b\n\x03id2\x18\x06 \x01(\x05\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12\x0c\n\x04name\x18\x0b \x01(\t\x12\x13\n\x0b\x63ountryCode\x18\x0c \x01(\x05\x12\x11\n\tworldTime\x18\r \x01(\x07\x12\x0b\n\x03\x66\x31\x36\x18\x10 \x01(\x05\"I\n\nGTPC21_6_1\x12\r\n\x05seqno\x18\x01 \x01(\x05\x12 \n\x0bplayerInfos\x18\x02 \x03(\x0b\x32\x0b.PlayerInfo\x12\n\n\x02\x66\x33\x18\x03 \x01(\x05\"+\n\x08GTPC21_6\x12\x1f\n\ngtpc21_6_1\x18\x01 \x03(\x0b\x32\x0b.GTPC21_6_1\":\n\x08GTPC21_4\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\n\n\x02\x66\x36\x18\x06 \x01(\t\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12\n\n\x02\x66\x38\x18\x08 \x01(\x05\"\"\n\x08GTPC21_8\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\"k\n\x06GTPC21\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\x1b\n\x08gtpc21_4\x18\x04 \x01(\x0b\x32\t.GTPC21_4\x12\x1b\n\x08gtpc21_6\x18\x06 \x01(\x0b\x32\t.GTPC21_6\x12\x1b\n\x08gtpc21_8\x18\x08 \x01(\x0b\x32\t.GTPC21_8\"H\n\x12GameToPhoneCommand\x12\r\n\x05seqno\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\x17\n\x06gtpc21\x18\x15 \x01(\x0b\x32\x07.GTPC21\"|\n\x0bGameToPhone\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\n\n\x02id\x18\x03 \x01(\x05\x12\n\n\x02\x66\x34\x18\x04 \x01(\x05\x12\n\n\x02\x66\x36\x18\x06 \x01(\x05\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12%\n\x08\x63ommands\x18\x0b \x03(\x0b\x32\x13.GameToPhoneCommand\"f\n\rZMLClientInfo\x12\x12\n\nappVersion\x18\x01 \x01(\t\x12\x17\n\x0fsystemOSVersion\x18\x02 \x01(\t\x12\x10\n\x08systemOS\x18\x03 \x01(\t\x12\x16\n\x0esystemHardware\x18\x04 \x01(\t\"A\n\x15ZMLClientCapabilities\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\x1c\n\x04info\x18\x05 \x01(\x0b\x32\x0e.ZMLClientInfo\"\xa9\x01\n\x12PhoneToGameCommand\x12\r\n\x05seqno\x18\x01 \x01(\x05\x12\x0f\n\x07\x63ommand\x18\x02 \x01(\x05\x12\x0f\n\x07subject\x18\x03 \x01(\x05\x12\n\n\x02\x66\x35\x18\x05 \x01(\x05\x12\n\n\x02\x66\x36\x18\x06 \x01(\t\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12\x10\n\x08playerId\x18\x13 \x01(\x05\x12,\n\x0c\x63\x61pabilities\x18\x15 \x01(\x0b\x32\x16.ZMLClientCapabilities\"L\n\x0bPhoneToGame\x12\n\n\x02id\x18\x01 \x01(\x05\x12$\n\x07\x63ommand\x18\x02 \x01(\x0b\x32\x13.PhoneToGameCommand\x12\x0b\n\x03\x66\x31\x30\x18\n \x01(\x05\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'zwiftMessages_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PLAYERSTATE._serialized_start=24
  _PLAYERSTATE._serialized_end=478
  _CLIENTTOSERVER._serialized_start=481
  _CLIENTTOSERVER._serialized_end=690
  _SEGMENTRESULT._serialized_start=693
  _SEGMENTRESULT._serialized_end=919
  _SEGMENTRESULTS._serialized_start=921
  _SEGMENTRESULTS._serialized_end=1043
  _UNKNOWNMESSAGE1._serialized_start=1045
  _UNKNOWNMESSAGE1._serialized_end=1062
  _UNKNOWNMESSAGE._serialized_start=1064
  _UNKNOWNMESSAGE._serialized_end=1080
  _SERVERTOCLIENT._serialized_start=1083
  _SERVERTOCLIENT._serialized_end=1308
  _WORLDATTRIBUTES._serialized_start=1310
  _WORLDATTRIBUTES._serialized_end=1427
  _WORLDATTRIBUTE._serialized_start=1429
  _WORLDATTRIBUTE._serialized_end=1465
  _EVENTSUBGROUPPROTOBUF._serialized_start=1468
  _EVENTSUBGROUPPROTOBUF._serialized_end=1637
  _RIDERATTRIBUTES._serialized_start=1640
  _RIDERATTRIBUTES._serialized_end=1881
  _RIDERATTRIBUTES_ATTRIBUTEMESSAGE._serialized_start=1774
  _RIDERATTRIBUTES_ATTRIBUTEMESSAGE._serialized_end=1881
  _PROFILES._serialized_start=1883
  _PROFILES._serialized_end=1921
  _PROFILE._serialized_start=1924
  _PROFILE._serialized_end=2318
  _VECTOR3._serialized_start=2320
  _VECTOR3._serialized_end=2362
  _PLAYERINFO._serialized_start=2365
  _PLAYERINFO._serialized_end=2538
  _GTPC21_6_1._serialized_start=2540
  _GTPC21_6_1._serialized_end=2613
  _GTPC21_6._serialized_start=2615
  _GTPC21_6._serialized_end=2658
  _GTPC21_4._serialized_start=2660
  _GTPC21_4._serialized_end=2718
  _GTPC21_8._serialized_start=2720
  _GTPC21_8._serialized_end=2754
  _GTPC21._serialized_start=2756
  _GTPC21._serialized_end=2863
  _GAMETOPHONECOMMAND._serialized_start=2865
  _GAMETOPHONECOMMAND._serialized_end=2937
  _GAMETOPHONE._serialized_start=2939
  _GAMETOPHONE._serialized_end=3063
  _ZMLCLIENTINFO._serialized_start=3065
  _ZMLCLIENTINFO._serialized_end=3167
  _ZMLCLIENTCAPABILITIES._serialized_start=3169
  _ZMLCLIENTCAPABILITIES._serialized_end=3234
  _PHONETOGAMECOMMAND._serialized_start=3237
  _PHONETOGAMECOMMAND._serialized_end=3406
  _PHONETOGAME._serialized_start=3408
  _PHONETOGAME._serialized_end=3484
# @@protoc_insertion_point(module_scope)
