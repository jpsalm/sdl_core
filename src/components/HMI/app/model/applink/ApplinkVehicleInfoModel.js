/**
 * @name MFT.ApplinkVehicleInfoModel
 * 
 * @desc Applink model with vehicle information used instead of CAN network. VehicleInfoModel is simulation of real CAN network. 
 * 
 * @category    Model
 * @filesource  app/model/applink/ApplinkVehicleInfoModel.js
 * @version     1.0
 *
 * @author      Andriy Melnik
 */
 
MFT.ApplinkVehicleInfoModel = Em.Object.create({

    /**
     * Stored VehicleInfo transmission state Data
     */
    vehicleInfoPRNDL: [
        {
            name:   "PARK",
            id:     0
        },
        {
            name:   "REVERSE",
            id:     1
        },
        {
            name:   "NEUTRAL",
            id:     2
        },
        {
            name:   "FORWARD_DRIVE_2",
            id:     3
        },
        {
            name:   "LOWGEAR",
            id:     4
        }
    ],

    /**
     * Stored VehicleInfo Data
     */
    ecuDIDData:[
        {
            'data':     "ECU 1 Test Data"
        },
        {
            'data':     "ECU 2 Test Data"
        }
    ],

    /**
     * Type of current vehicle: make of the vehicle, model of the vehicle,
     * model Year of the vehicle, trim of the vehicle.
     * @type {Object}
     */ 
    vehicleType:{
      make:       "Ford",
      model:      "Fiesta",
      modelYear:  2013,
      trim:       "SE"  
    },

    /**
     * Stored VehicleInfo Data
     */
    vehicleData: {
        'VEHICLEDATA_SPEED':{
            data:   80,
            type:   'speed'
        },
        'VEHICLEDATA_ENGINERPM':{
            data:   5000,
            type:   'rpm'
        },
        'VEHICLEDATA_FUELLEVEL':{
            data:   0.2,
            type:   'fuelLevel'
        },
        'VEHICLEDATA_FUELECONOMY':{
            data:   0.1,
            type:   'avgFuelEconomy'
        },
        'VEHICLEDATA_BATTVOLTS':{
            data:   12.5,
            type:   'batteryVoltage'
        },
        'VEHICLEDATA_EXTERNTEMP':{
            data:   40,
            type:   'externalTemperature'
        },
        'VEHICLEDATA_VIN':{
            data:   '52-452-52-752',
            type:   'vin'
        },
        'VEHICLEDATA_PRNDLSTATUS':{
            data:   'PARK',
            type:   'prndl'
        },
        'VEHICLEDATA_TIREPRESSURE':{
            data:   {
                'leftFront': {
                    'status':   'NORMAL',
                    'pressure': 2
                }
            },
            type:   'tirePressure'
        },
        'VEHICLEDATA_BATTERYPACKVOLTAGE':{
            data:   12.5,
            type:   'batteryPackVoltage'
        },
        'VEHICLEDATA_BATTERYCURRENT':{
            data:   7,
            type:   'batteryPackCurrent'
        },
        'VEHICLEDATA_BATTERYTEMPERATURE':{
            data:   30,
            type:   'batteryPackTemperature'
        },
        'VEHICLEDATA_ENGINETORQUE':{
            data:   650,
            type:   'engineTorque'
        },
        'VEHICLEDATA_ODOMETER':{
            data:   0,
            type:   'odometer'
        },
        'VEHICLEDATA_TRIPODOMETER':{
            data:   0,
            type:   'tripOdometer'
        },
        'VEHICLEDATA_GENERICBINARY':{
            data:   165165650,
            type:   'genericbinary'
        },
        'VEHICLEDATA_SATESN':{
            data:   165165650,
            type:   'satRadioESN'
        },
        'VEHICLEDATA_GPS':{
            data:   165165650,
            type:   'gps'
        },
        'VEHICLEDATA_RAINSENSOR':{
            data:   165165650,
            type:   'rainSensor'
        }

    },

    /**
     * Method calls GetVehicleType response
     */
    getVehicleType: function( id ){
        FFW.VehicleInfo.GetVehicleTypeResponse( this.vehicleType, id );
    },

    /**
     * Applink VehicleInfo.GetDTCs handler
     * fill data for response about vehicle errors
     */
    vehicleInfoGetDTCs: function( params, id ){
        var data = {},
            i = 0,
            info = "Inormation about reported DTC's",
            result = "";

        for(i = 0; i < 3; i++) {
            data[i] = {};
            data[i].identifier =  "0";
            data[i].statusByte =  "0";
        }

        result = "SUCCESS";

        if(params.encrypted){
            result = 'ENCRYPTED';
            FFW.AppLinkCoreClient.SendData( data );
            FFW.VehicleInfo.vehicleInfoGetDTCsResponse( null, info, result, id );
        }else{
            FFW.VehicleInfo.vehicleInfoGetDTCsResponse( data, info, result, id );
        }
    },

    /**
     * Applink VehicleInfo.ReadDID handler
     * send response about vehicle conditions
     */
    vehicleInfoReadDID: function( params, id ){
        var data = [],
            i = 0,
            info = '',
            dataResult = [],
            resultCode = "";
        if(this.ecuDIDData[params.ecuName].data){
            info = this.ecuDIDData[params.ecuName].data;
            result = "SUCCESS";
        }else{
            info = "";
            result = "INVALID_DATA";
        }

        
        for(i = 0; i < params.didLocation.length; i++) {
            if(i < 10){
                dataResult[i] = 'SUCCESS';
                data[i] =       0;
            }else{
                dataResult[i] = "INVALID_DATA";
                data[i] =       0;
            }
        }

        if(params.encrypted){
            result = 'ENCRYPTED';
            FFW.AppLinkCoreClient.SendData( data );
            FFW.VehicleInfo.vehicleInfoReadDIDResponse( null, null, info, result, id );
        }else{
            FFW.VehicleInfo.vehicleInfoReadDIDResponse( dataResult, data, info, result, id );
        }
    },

    /** 
     * Function returns response message to VehicleInfoRPC
     */
    getVehicleData: function( message ){

        return this.vehicleData[message.dataType].data;

    },

    /** 
     * Function send all vehicle conditions on FFW.VehicleInfo.OnVehicleData
     * fo notification when data changes
     */
    onVehicleDataChanged: function(){

        var jsonData = {};
        for(var i  in this.vehicleData) {
          jsonData[i] = this.vehicleData[i];
        }
        FFW.VehicleInfo.OnVehicleData(jsonData);

    }.observes('this.vehicleData.VEHICLEDATA_PRNDLSTATUS.data')
});
 