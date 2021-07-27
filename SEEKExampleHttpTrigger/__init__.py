import json
import logging
import os

import azure.functions as func
import eml_parser
import vt


def build_response(message: str, success: bool = False) -> str:
    response = {}
    response['success'] = success
    response['message'] = message

    return json.dumps(response, indent=4)


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function received a request.')
    # Setup response JSON message for subsquent LogicApps
    # {"success": true, "message": "Some message"}

    try:
        # Process JSON incoming request in the following format
        # {'eml': 'EML TEXT'}
        req_body = req.get_json()

    except ValueError:
        return func.HttpResponse(
            build_response(message='Invalid JSON body', status_code=418))

    # Extract EML text
    eml = req_body.get('eml')

    if eml is None:
        return func.HttpResponse(build_response(message='Empty EML element'),
                                 status_code=418)

    # Setup Eml parser and parse eml with attachments
    ep = eml_parser.EmlParser(include_attachment_data=True)
    parsed_eml = ep.decode_email_bytes(eml.encode(encoding='UTF-8'))

    # Extract relevant information
    subject = parsed_eml.get('header').get('subject')

    # Attachment (assuming there's only 1 hence index is hard coded as 0)
    # Extracted subject / filename / hash
    filename = parsed_eml.get('attachment')[0].get('filename')
    sha1hash = parsed_eml.get('attachment')[0].get('hash').get('sha1')

    # Setup VT / Process VT
    # Since it's MSTICpy you may not be restricted VT
    vt_api_key = os.environ['VT_API_KEY']

    # Inject a mailcious sha1
    sha1hash = '92cc568e255250def353bcd64fb9279468cedce4'

    with vt.Client(vt_api_key) as client:
        try:
            file = client.get_object(f'/files/{sha1hash}')

            return func.HttpResponse(
                build_response(message=f'{file.last_analysis_stats}',
                               success=True))

        except vt.APIError as e:
            return func.HttpResponse(build_response(
                message=f'File not found {sha1hash}. Reason {e}',
                success=True),
                                     status_code=200)

    # Finished EML analysis, create a JSON response with enough data for the next stage to use
    return func.HttpResponse(build_response(
        f'{subject} / {filename} / {sha1hash}', status=True),
                             status_code=200)
