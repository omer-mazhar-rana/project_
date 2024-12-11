from django.shortcuts import render
import pytz
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from datetime import datetime, timedelta
from django.db.models import Q

from project_emr_auth.timezone import TimeZoneMixin
from .serializers import (
    AppointmentsSerializer,
    ChooseServicesSerializer,
    OfficeTimingsSerializer,
    SearchPatientSerializer,
)
from project_emr_auth.models import (
    Clinic
)
from .models import (
    Appointments
)
from EMR_patients.models import Patient
from EMR_services.models import Services
from project_emr_auth.models import BasicOfficeSettings
from EMR_patients.views import PateintSummaryPostMixin


class UpcomingAppointmentsView(TimeZoneMixin, PateintSummaryPostMixin, APIView):
    serializer_class = AppointmentsSerializer

    def get(self, request):
        clinic = self.helper(request)[0]
        time = self.set_timezone(request)[1]
        
        start_of_today = time.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_today = time.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        start_of_today_utc = start_of_today.astimezone(pytz.utc)
        end_of_today_utc = end_of_today.astimezone(pytz.utc)

        appointments = Appointments.objects.filter(
            clinic_id=clinic, 
            appointment_date__range=(start_of_today_utc, end_of_today_utc)
        )

        serializer = self.serializer_class(appointments, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class AppointmentsView(TimeZoneMixin, PateintSummaryPostMixin,APIView):
    serializer_class = AppointmentsSerializer
    def post(self, request):
            clinic = self.helper(request)[0]
            request.data["clinic"] = clinic
            now = self.set_timezone(request)[0]
            request.data["registered_date"] = now
            appointment_date = request.data.get("appointment_date")
            if appointment_date:
                try:
                    datetime.strptime(appointment_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    try:
                        datetime.strptime(appointment_date, "%Y-%m-%dT%H:%M:%SZ")
                    except ValueError:
                        return Response("Invalid appointment date format", status=status.HTTP_400_BAD_REQUEST)

                if now > datetime.strptime(appointment_date, "%Y-%m-%dT%H:%M:%SZ").date():
                    return Response("Appointment date cannot be in the past", status=status.HTTP_400_BAD_REQUEST)

            try:
                appointment_exists = Appointments.objects.get(clinic_id=clinic, doctor_id=request.data["doctor_id"], appointment_date=request.data["appointment_date"])
            except:
                appointment_exists = None
            
            if appointment_exists:
                return Response("Doctor not available for this time", status=status.HTTP_406_NOT_ACCEPTABLE)
            
            serializer = self.serializer_class(data=request.data)
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self,request,pk):
        clinic = self.helper(request)[0]
        instance = Appointments.objects.get(clinic_id=clinic, id=pk)
        request.data["clinic"] = clinic
        serializer = self.serializer_class(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        clinic = self.helper(request)[0]
        time = self.set_timezone(request)[1]
        
        start_of_today = time.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_today = time.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        start_of_today_utc = start_of_today.astimezone(pytz.utc)
        end_of_today_utc = end_of_today.astimezone(pytz.utc)

        appointments_today = Appointments.objects.filter(
            clinic_id=clinic,
            appointment_date__gte=start_of_today_utc,
            appointment_date__lte=end_of_today_utc
        )
        appointments_today_serializer = self.serializer_class(appointments_today, many=True)

        start_of_tomorrow = start_of_today + timedelta(days=1)
        end_of_tomorrow = end_of_today + timedelta(days=1)
        start_of_tomorrow_utc = start_of_tomorrow.astimezone(pytz.utc)
        end_of_tomorrow_utc = end_of_tomorrow.astimezone(pytz.utc)

        appointments_tomorrow = Appointments.objects.filter(
            clinic_id=clinic,
            appointment_date__gte=start_of_tomorrow_utc,
            appointment_date__lte=end_of_tomorrow_utc
        )
        appointments_tomorrow_serializer = self.serializer_class(appointments_tomorrow, many=True)

        response_data = {
            "appointments_today": appointments_today_serializer.data,
            "appointments_tomorrow": appointments_tomorrow_serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)


    def delete(self, request, pk):
        clinic = self.helper(request)[0]
        instance = Appointments.objects.get(clinic_id=clinic, id=pk)
        if instance:
            instance.delete()
            return Response("deleted",status=status.HTTP_200_OK)

class GetAppointmentDate(PateintSummaryPostMixin, APIView):
    serializer_class = AppointmentsSerializer
    def get(self, request):
        clinic = self.helper(request)[0]
        q = request.GET.get("q", None)
        instance = Appointments.objects.get(clinic_id=clinic, appointment_date=q)
        serializer = self.serializer_class(instance)
        return Response(serializer.data)


class SearchPatientView(PateintSummaryPostMixin,APIView):
    serializer_class = SearchPatientSerializer
    def get(self, request):
        clinic = self.helper(request)[0]       
        search_param = request.GET.get("q",None)

        if search_param:
            search_terms = search_param.split()
            query = Q(clinic_id=clinic)

            if len(search_terms) == 2:
                first_name_term = search_terms[0]
                second_name_term = search_terms[1]
                query &= (
                    Q(first_name__icontains=first_name_term, last_name__icontains=second_name_term) |
                    Q(first_name__icontains=first_name_term, middle_name__icontains=second_name_term) |
                    Q(middle_name__icontains=first_name_term, last_name__icontains=second_name_term) |
                    Q(last_name__icontains=first_name_term, middle_name__icontains=second_name_term)
                )
            elif len(search_terms) == 3:
                first_name_term = search_terms[0]
                middle_name_term = search_terms[1]
                last_name_term = search_terms[2]
                query &= (
                    Q(first_name__icontains=first_name_term, middle_name__icontains=middle_name_term, last_name__icontains=last_name_term)
                )
            else:
                for term in search_terms:
                    query &= (
                        Q(mrn_number__icontains=term) |
                        Q(first_name__icontains=term) |
                        Q(last_name__icontains=term) |
                        Q(middle_name__icontains=term) |
                        Q(govId__icontains=term) |
                        Q(passport__icontains=term) |
                        Q(license__icontains=term) |
                        Q(patient_phone__icontains=term) |
                        Q(ssn__icontains=term)
                    )
                    
            instance = Patient.objects.filter(query)
        else:
            instance = Patient.objects.none()

        serializer = self.serializer_class(instance, many=True)
        
        return Response(serializer.data,status=status.HTTP_200_OK)
    
class ChooseServiceView(PateintSummaryPostMixin,APIView):
    serializer_class = ChooseServicesSerializer
    def get(self,request):
        clinic = self.helper(request)[0]
        instance = Services.objects.filter(clinic_id=clinic)
        serializer = self.serializer_class(instance, many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class OfficeTimingsView(PateintSummaryPostMixin,APIView):
    serializer_class = OfficeTimingsSerializer
    def get(self,request):
        clinic = self.helper(request)[0]
        instance = BasicOfficeSettings.objects.filter(clinic_id=clinic)
        serializer = self.serializer_class(instance,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    