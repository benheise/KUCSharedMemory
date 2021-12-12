#pragma once

#define ENTITY_SIZE_DEF				0x42E0
#define OFFSET_ENTITYLIST			0x194cb58  	// cl_entitylist
#define OFFSET_LOCAL_ENT			0x1cfbdb8  	// LocalPlayer
#define OFFSET_NAMELIST				0xb9c9360  	// NameList
#define OFFSET_RENDER				0x74e7b28  	// ViewRender
#define OFFSET_MATRIX				0x1b3bd0	// ViewMatrix0x01b8
#define OFFSET_INPUT				0x01ce51a0	// .?AVCInput@@
#define OFFSET_DISABLE_BLOOM		0x01cf2680 	// mat_disable_bloom
#define OFFSET_THIRD_PERSON			0x01932920 	// thirdperson_override

#define OFFSET_NAME_INDEX			0x38
#define OFFSET_SHIELD				0x0170		// m_shieldHealth	
#define OFFSET_MAX_SHIELD			0x0174		// m_shieldHealthMax
#define OFFSET_ITEM_ID				0x1698
#define OFFSET_HEALTH				0x0438		// m_iHealth
#define OFFSET_TEAM					0x0448		// m_iTeamNum
#define OFFSET_NAME					0x0589		// m_iName
#define OFFSET_LIFE_STATE			0x0798		// m_lifeState
#define OFFSET_VISIBLE_TIME			0x1af4
#define OFFSET_BLEED_OUT_STATE		0x2718		// m_bleedoutState
#define OFFSET_OBSERVING_TARGET		0x33b8		// m_hObserverTarget
#define OFFSET_ZOOM_FOV             0x1700 + 0xb8 //m_playerData + m_curZoomFOV
#define OFFSET_SKIN_OVERRIDE		0x17f0		//m_skinOverride

#define OFFSET_BULLET_SPEED			0x1ef0		// m_flProjectileSpeed
#define OFFSET_BULLET_GRAVITY		OFFSET_BULLET_SPEED + 0x8

#define OFFSET_CHARGE_LEVEL			0x1810		// m_lastChargeLevel
#define OFFSET_NAME_INDEX			0x185c		// m_weaponNameIndex
#define OFFSET_CURRENT_WEAPON		0x1a8c		// m_latestPrimaryWeapons
#define OFFSET_ORIGIN				0x014c		// m_vecAbsOrigin
#define OFFSET_BONES				0x0f38		// m_bConstrainBetweenEndpoints || m_nForceBone + 0x48
#define OFFSET_AIMPUNCH				0x2480		// m_currentFrameLocalPlayer.m_vecPunchWeapon_Angle
#define OFFSET_CAMERAPOS			0x1F20
#define OFFSET_VIEWANGLES			0x257c - 0x14		// ammoPoolCapacity - 0x14
#define OFFSET_BREATH_ANGLES		(OFFSET_VIEWANGLES - 0x10)
#define OFFSET_ARMOR_TYPE			0x44a4		// DT_Player - m_armorType

#define OFFSET_SCRIPT_ID			0x1698		// m_customScriptInt
#define OFFSET_WEAPON_READY_TIME	0x1698		// m_nextReadyTime

#define OFFSET_SIGNIFIER			0x0580		// m_iSignifierName
#define OFFSET_ABS_VELOCITY			0x0140		// C_Player : m_vecAbsVelocity

// DT_HighlightSettings
#define OFFSET_GLOW_DISTANCE		0x3B4
#define OFFSET_GLOW_COLOR			0x1D0 // m_highlightParams + 0x18
#define OFFSET_GLOW_MODE			0x2C4 // m_highlightFunctionBits + 0x4
#define OFFSET_GLOW_ENABLE			0x3C8
#define OFFSET_GLOW_THROUGH_WALLS	0x3D0