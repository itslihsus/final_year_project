from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .phishing_url_detection import DETECTION

class URLPredictionApiView(APIView):
    def post(self, request):
        url = request.data.get('url')
        if not url:
            return Response({"error": "URL not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            detection = DETECTION()
            prediction = detection.featureExtractions(url)
            return Response({"success": True, "prediction": prediction})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)







