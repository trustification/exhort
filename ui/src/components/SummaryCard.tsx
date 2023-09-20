import {
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  Icon,
  List,
  ListItem,
  Text,
  TextContent,
  Grid,
  GridItem, capitalize, CardFooter, Flex, FlexItem,
} from '@patternfly/react-core';
import ShieldAltIcon from '@patternfly/react-icons/dist/esm/icons/shield-alt-icon';
import ExclamationTriangleIcon from '@patternfly/react-icons/dist/esm/icons/exclamation-triangle-icon';
import RedhatIcon from '@patternfly/react-icons/dist/esm/icons/redhat-icon';

import { Provider } from '../api/report';
import { useAppContext } from '../App';
import { ChartCard } from './ChartCard';


// export const SummaryCard = ({ provider }: { provider: Provider }) => {
export const SummaryCard = () => {
  const appContext = useAppContext();
  const providers = Object.keys(appContext.report);
    return (
        <Card isFlat isFullHeight>
          <CardHeader>
            <CardTitle>
              <Icon isInline status="info">
                <ExclamationTriangleIcon style={{fill: "#f0ab00"}}/>
              </Icon>&nbsp;Red Hat Overview of security Issues</CardTitle>
          </CardHeader>
          <Divider />
          <CardBody>
            <DescriptionListGroup>
              <DescriptionListDescription>
                <DescriptionListTerm>
                    Below is a list of dependencies affected with CVE.
                  </DescriptionListTerm>
              </DescriptionListDescription>
            </DescriptionListGroup>
            <DescriptionList isAutoFit>
              {providers?.map((name, index) => {
                const provider = appContext.report[name];
                return (
                    <DescriptionListGroup key={index}>
                      <DescriptionListTerm>{name}</DescriptionListTerm>
                      <DescriptionListDescription>
                        <ChartCard provider={provider} />
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                )
              })
              }
            </DescriptionList>
          </CardBody>
            <Divider/>
            <CardFooter>
              <DescriptionList
                  columnModifier={{
                    default: '2Col',
                  }}
              >
                <DescriptionListGroup>
                  <DescriptionListTerm>
                    <Icon isInline status="info">
                      <RedhatIcon style={{fill: "#cc0000"}}/>
                    </Icon>&nbsp;

                    Red Hat Remediations
                  </DescriptionListTerm>
                  <DescriptionListDescription>
                    <List isPlain>
                      <ListItem>
                        Below is a list of dependencies affected with CVE.
                      </ListItem>
                    </List>
                  </DescriptionListDescription>
                </DescriptionListGroup>

                <DescriptionListGroup>
                  <DescriptionListTerm>
                    Subscribe to stay updated
                  </DescriptionListTerm>
                  <DescriptionListDescription>
                    <List isPlain>
                      <ListItem>
                        Dependencies with high common vulnerabilities and exposures (CVE) score.
                      </ListItem>
                    </List>
                  </DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
          </CardFooter>
        </Card>
    );
  };
